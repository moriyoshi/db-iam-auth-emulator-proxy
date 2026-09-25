package iamproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"
)

// Dialer opens a network connection. Its signature matches
// net.Dialer.DialContext, pgconn.DialFunc, and go-mysql's client.Dialer.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Options configure an embedded emulator beyond its Config.
type Options struct {
	// Certificate is served by database listeners and the HTTPS credential
	// endpoint. When nil, Config.TLSCert and Config.TLSKey are loaded; when
	// those are empty too, a self-signed certificate is generated for
	// localhost, loopback addresses, and every listener hostname.
	Certificate *tls.Certificate
	// Logger receives operational messages. Nil discards them.
	Logger *slog.Logger
	// UpstreamDialer opens backend database connections. It is only ever
	// called with a listener's configured upstream address. Nil uses
	// net.Dialer.
	UpstreamDialer Dialer
	// InMemory serves database listeners only through Emulator.DialContext
	// and binds no TCP port for them. Listener addresses must then name a
	// fixed port, because AWS tokens sign the endpoint host and port.
	// Credential HTTP endpoints are always bound to TCP.
	InMemory bool
}

// Emulator is a running set of database listeners and credential endpoints.
type Emulator struct {
	svc      *service
	tls      *tls.Config
	leaf     *x509.Certificate
	log      *slog.Logger
	dial     Dialer
	cancels  sync.Map
	memory   map[string]*memListener // by listener name
	routes   map[string]string       // dial address to listener name
	httpURL  string
	httpsURL string
	stop     context.CancelFunc
	done     chan struct{}
}

// Start validates a copy of c, binds its endpoints, and serves them until ctx
// is cancelled or Close is called. An empty HTTPListen and listener ports of
// 0 bind ephemeral loopback ports; Config reports the bound addresses.
func Start(ctx context.Context, c *Config, o Options) (*Emulator, error) {
	c = c.clone()
	if c.HTTPListen == "" {
		c.HTTPListen = "127.0.0.1:0"
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	e := &Emulator{log: o.Logger, dial: o.UpstreamDialer, memory: map[string]*memListener{}, routes: map[string]string{}, done: make(chan struct{})}
	if e.log == nil {
		e.log = slog.New(slog.DiscardHandler)
	}
	if e.dial == nil {
		e.dial = (&net.Dialer{}).DialContext
	}
	cert, err := serverCertificate(c, o.Certificate)
	if err != nil {
		return nil, err
	}
	if e.leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
		return nil, err
	}
	e.tls = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	var closers []io.Closer
	fail := func(err error) (*Emulator, error) {
		for _, v := range closers {
			_ = v.Close()
		}
		return nil, err
	}
	var tcp []net.Listener
	for i := range c.Listeners {
		l := &c.Listeners[i]
		if o.InMemory {
			if _, port, _ := net.SplitHostPort(l.Listen); port == "0" {
				return fail(fmt.Errorf("listener %s: in-memory listeners need a fixed port", l.Name))
			}
			continue
		}
		ln, err := net.Listen("tcp", l.Listen)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", l.Name, err))
		}
		closers = append(closers, ln)
		tcp = append(tcp, ln)
		l.Listen = ln.Addr().String()
	}
	for _, l := range c.Listeners {
		_, port, _ := net.SplitHostPort(l.Listen)
		addrs := []string{l.Listen}
		if l.Hostname != "" {
			addrs = append(addrs, net.JoinHostPort(l.Hostname, port))
		}
		for _, a := range addrs {
			if other, ok := e.routes[a]; ok && other != l.Name {
				return fail(fmt.Errorf("listeners %s and %s share dial address %s", other, l.Name, a))
			}
			e.routes[a] = l.Name
		}
		e.memory[l.Name] = newMemListener(l.Listen)
		closers = append(closers, e.memory[l.Name])
	}
	httpLn, err := net.Listen("tcp", c.HTTPListen)
	if err != nil {
		return fail(err)
	}
	closers = append(closers, httpLn)
	c.HTTPListen = httpLn.Addr().String()
	e.httpURL = "http://" + c.HTTPListen
	if c.PublicURL == "" {
		c.PublicURL = e.httpURL
	}
	var httpsLn net.Listener
	if c.HTTPSListen != "" {
		if httpsLn, err = net.Listen("tcp", c.HTTPSListen); err != nil {
			return fail(err)
		}
		closers = append(closers, httpsLn)
		c.HTTPSListen = httpsLn.Addr().String()
		e.httpsURL = "https://" + c.HTTPSListen
	}
	if e.svc, err = newService(c); err != nil {
		return fail(err)
	}
	ctx, e.stop = context.WithCancel(ctx)
	e.serve(ctx, tcp, httpLn, httpsLn)
	return e, nil
}

func (e *Emulator) serve(ctx context.Context, tcp []net.Listener, httpLn, httpsLn net.Listener) {
	c := e.svc.Config
	var wg sync.WaitGroup
	for i, ln := range tcp {
		l := c.Listeners[i]
		wg.Go(func() { e.accept(ctx, ln, l) })
		e.log.Info("database listener", "name", l.Name, "addr", l.Listen)
	}
	for _, l := range c.Listeners {
		ln := e.memory[l.Name]
		wg.Go(func() { e.accept(ctx, ln, l) })
	}
	handler := e.svc.HTTPHandler()
	plain := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	servers := []*http.Server{plain}
	wg.Go(func() { e.serveHTTP(plain, httpLn) })
	e.log.Info("credential endpoints", "addr", c.HTTPListen)
	if httpsLn != nil {
		srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
		servers = append(servers, srv)
		wg.Go(func() { e.serveHTTP(srv, tls.NewListener(httpsLn, e.tls)) })
		e.log.Info("TLS credential endpoints", "addr", c.HTTPSListen)
	}
	go func() {
		<-ctx.Done()
		for _, ln := range tcp {
			_ = ln.Close()
		}
		for _, ln := range e.memory {
			_ = ln.Close()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, srv := range servers {
			_ = srv.Shutdown(shutdownCtx)
		}
		wg.Wait()
		close(e.done)
	}()
}

func (e *Emulator) serveHTTP(srv *http.Server, ln net.Listener) {
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		e.log.Error("credential endpoint", "addr", ln.Addr().String(), "err", err)
	}
}

// Close stops accepting connections, closes listeners, and waits for accept
// loops and HTTP servers to finish. Relayed sessions end when either side
// closes.
func (e *Emulator) Close() error {
	e.stop()
	<-e.done
	return nil
}

// Done is closed after the emulator has shut down.
func (e *Emulator) Done() <-chan struct{} { return e.done }

// Config returns a copy of the effective configuration, with bound
// addresses and the derived public URL filled in.
func (e *Emulator) Config() *Config { return e.svc.Config.clone() }

// HTTPURL is the base URL of the plain HTTP credential endpoints.
func (e *Emulator) HTTPURL() string { return e.httpURL }

// HTTPSURL is the base URL of the TLS credential endpoints, or empty when
// HTTPSListen is not configured.
func (e *Emulator) HTTPSURL() string { return e.httpsURL }

// ListenerAddr returns the address a named database listener serves.
func (e *Emulator) ListenerAddr(name string) (string, bool) {
	for _, l := range e.svc.Config.Listeners {
		if l.Name == name {
			return l.Listen, true
		}
	}
	return "", false
}

// CertPool trusts the emulator's serving certificate.
func (e *Emulator) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(e.leaf)
	return pool
}

// ClientTLSConfig returns a client configuration that trusts the emulator's
// certificate. Drivers that fill ServerName from the dialed host, such as
// go-sql-driver/mysql, verify it against the listener hostname.
func (e *Emulator) ClientTLSConfig() *tls.Config {
	return &tls.Config{RootCAs: e.CertPool(), MinVersion: tls.VersionTLS12}
}

// CertificatePEM returns the serving certificate, for clients configured by
// file path.
func (e *Emulator) CertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.leaf.Raw})
}

// DialContext opens an in-memory connection to the database listener whose
// address, or hostname and port, equals addr. It never falls back to the
// network. Pass it as a driver dial hook, such as pgconn.Config.DialFunc or
// go-mysql's client.Dialer.
func (e *Emulator) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// pgconn dials a connection's RemoteAddr network for cancel requests.
	switch network {
	case "tcp", "tcp4", "tcp6", "", memAddr("").Network():
	default:
		return nil, fmt.Errorf("iamproxy: unsupported network %q", network)
	}
	name, ok := e.routes[addr]
	if !ok {
		return nil, fmt.Errorf("iamproxy: no database listener for %s", addr)
	}
	ln := e.memory[name]
	client, server := memPipe("client", addr)
	select {
	case ln.conns <- server:
		return client, nil
	case <-ln.done:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (e *Emulator) accept(ctx context.Context, ln net.Listener, l Listener) {
	sem := make(chan struct{}, 256)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			e.log.Warn("accept", "listener", l.Name, "err", err)
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			return
		}
		go func() {
			defer func() { <-sem; _ = conn.Close() }()
			var err error
			if l.Engine == "postgres" {
				err = e.servePostgres(ctx, conn, l)
			} else {
				err = e.serveMySQL(ctx, conn, l)
			}
			if err != nil && !errors.Is(err, io.EOF) {
				e.log.Warn("session", "listener", l.Name, "err", err)
			}
		}()
	}
}

func serverCertificate(c *Config, cert *tls.Certificate) (tls.Certificate, error) {
	if cert != nil {
		if len(cert.Certificate) == 0 {
			return tls.Certificate{}, errors.New("certificate has no chain")
		}
		return *cert, nil
	}
	if c.TLSCert != "" {
		return tls.LoadX509KeyPair(c.TLSCert, c.TLSKey)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "iamproxy"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}}
	seen := map[string]bool{"localhost": true, "127.0.0.1": true, "::1": true}
	for _, l := range c.Listeners {
		host, _, _ := net.SplitHostPort(l.Listen)
		for _, h := range []string{host, l.Hostname} {
			if h == "" || seen[h] {
				continue
			}
			seen[h] = true
			if ip := net.ParseIP(h); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else {
				tmpl.DNSNames = append(tmpl.DNSNames, h)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(a, b); done <- struct{}{} }()
	go func() { _, _ = io.Copy(b, a); done <- struct{}{} }()
	<-done
	_ = a.Close()
	_ = b.Close()
	<-done
}
