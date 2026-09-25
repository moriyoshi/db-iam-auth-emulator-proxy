package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"github.com/goccy/go-yaml"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/moriyoshi/db-iam-auth-emulator-proxy/iamproxy"
)

var containerSequence atomic.Uint64

type lockedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}
func (b *lockedBuffer) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.Buffer.String() }

func capture(ctx context.Context, binary string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
func freeAddress() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

func (h *Harness) startDatabase(kind string) error {
	if _, exists := h.databases[kind]; exists {
		return fmt.Errorf("%s already started", kind)
	}
	containerPort := "5432"
	if kind == "mysql" || kind == "mariadb" {
		containerPort = "3306"
	}
	name := fmt.Sprintf("iam-proxy-e2e-%d-%d-%s", os.Getpid(), containerSequence.Add(1), kind)
	args := []string{"run", "-d", "--name", name, "-p", "127.0.0.1::" + containerPort}
	if kind == "postgres" {
		args = append(args, "-e", "POSTGRES_USER=backend", "-e", "POSTGRES_PASSWORD=backpass", "-e", "POSTGRES_DB=testdb")
	} else if kind == "mysql" {
		args = append(args, "-e", "MYSQL_ROOT_PASSWORD=rootpass", "-e", "MYSQL_DATABASE=testdb", "-e", "MYSQL_USER=backend", "-e", "MYSQL_PASSWORD=backpass")
	}
	args = append(args, h.options.FixtureImage, "--database", kind)
	ctx, cancel := context.WithTimeout(h.ctx, h.options.FixtureTimeout)
	defer cancel()
	if out, err := capture(ctx, "docker", args...); err != nil {
		return fmt.Errorf("start %s: %w: %s", kind, err, out)
	}
	h.containers = append(h.containers, name)
	var addr string
	for ctx.Err() == nil {
		out, err := capture(ctx, "docker", "port", name, containerPort+"/tcp")
		if err == nil {
			addr = strings.TrimSpace(strings.Split(out, "\n")[0])
			if _, _, err = net.SplitHostPort(addr); err == nil {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if addr == "" {
		return fmt.Errorf("%s port not published: %w", kind, ctx.Err())
	}
	for ctx.Err() == nil {
		probeCtx, probeCancel := context.WithTimeout(ctx, 2*time.Second)
		var err error
		if kind == "postgres" {
			cfg, _ := pgconn.ParseConfig("sslmode=disable")
			host, port, _ := net.SplitHostPort(addr)
			number, _ := strconv.Atoi(port)
			cfg.Host = host
			cfg.Port = uint16(number)
			cfg.User = "backend"
			cfg.Password = "backpass"
			cfg.Database = "testdb"
			cfg.Fallbacks = nil
			var c *pgconn.PgConn
			c, err = pgconn.ConnectConfig(probeCtx, cfg)
			if err == nil {
				_ = c.Close(probeCtx)
			}
		} else {
			var c *sql.DB
			cfg := mysqlDriver.NewConfig()
			cfg.User = "backend"
			cfg.Passwd = "backpass"
			cfg.Net = "tcp"
			cfg.Addr = addr
			cfg.DBName = "testdb"
			c, err = sql.Open("mysql", cfg.FormatDSN())
			if err == nil {
				err = c.PingContext(probeCtx)
				_ = c.Close()
			}
		}
		probeCancel()
		if err == nil {
			h.databases[kind] = addr
			fmt.Fprintf(h.out, "✓ %s ready at %s\n", kind, addr)
			return nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
	return fmt.Errorf("%s readiness timed out: %w", kind, ctx.Err())
}

func makeCert(root string) (string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<60))
	if err != nil {
		return "", "", err
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	cp, kp := filepath.Join(root, "cert.pem"), filepath.Join(root, "key.pem")
	if err = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		return "", "", err
	}
	if err = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		return "", "", err
	}
	return cp, kp, nil
}

func (h *Harness) startProxy() error {
	if h.proxy != nil {
		return errors.New("proxy already started")
	}
	if h.databases["postgres"] == "" || h.databases["mysql"] == "" && h.databases["mariadb"] == "" {
		return errors.New("postgres() and mysql() or mariadb() are required before start_proxy()")
	}
	cp, kp, err := makeCert(h.root)
	if err != nil {
		return err
	}
	h.certPath = cp
	h.httpAddr, err = freeAddress()
	if err != nil {
		return err
	}
	h.httpsAddr, err = freeAddress()
	if err != nil {
		return err
	}
	c := &iamproxy.Config{HTTPListen: h.httpAddr, HTTPSListen: h.httpsAddr, PublicURL: "http://" + h.httpAddr, TLSCert: cp, TLSKey: kp}
	for _, provider := range []string{"aws", "google", "azure"} {
		for _, engine := range []string{"postgres", "mysql"} {
			addr, e := freeAddress()
			if e != nil {
				return e
			}
			name := provider + "-" + engine
			upstream := h.databases[engine]
			if engine == "mysql" && upstream == "" {
				upstream = h.databases["mariadb"]
			}
			l := iamproxy.Listener{Name: name, Listen: addr, Provider: provider, Engine: engine, Instance: "testdb", Hostname: "127.0.0.1", Region: "us-east-1", ResourceID: "db-test", Tenant: "tenant-1", Upstream: upstream, UpstreamTLS: "disable"}
			c.Listeners = append(c.Listeners, l)
			h.listeners[name] = listenerInfo{Addr: addr, Provider: provider, Engine: engine}
		}
	}
	c.Principals = []iamproxy.Principal{{ID: "alice", Email: "alice@example.com", Groups: []string{"readers"}, Grants: []string{"aws-postgres", "aws-mysql", "google-postgres", "google-mysql", "azure-postgres", "azure-mysql"}, BackendUser: "backend", BackendPassword: "backpass", AWSAccessKey: "AKIATEST", AWSSecretKey: "test-secret", AWSSessionToken: "imds-fixture-session", ECSAuthorizationToken: "ecs-auth", GoogleRefreshToken: "refresh", AzureClientID: "client-1", AzureClientSecret: "secret"}}
	h.awsConfigPath = filepath.Join(h.root, "empty-aws-config")
	if err = os.WriteFile(h.awsConfigPath, nil, 0600); err != nil {
		return err
	}
	h.googleADCPath = filepath.Join(h.root, "google-adc.json")
	googleADC, err := json.Marshal(map[string]string{
		"type": "authorized_user", "client_id": "mock-client", "client_secret": "mock-secret",
		"refresh_token": "refresh", "token_uri": "http://" + h.httpAddr + "/token",
	})
	if err != nil {
		return err
	}
	if err = os.WriteFile(h.googleADCPath, googleADC, 0600); err != nil {
		return err
	}
	if err = c.Validate(); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	configPath := filepath.Join(h.root, "config.yaml")
	if err = os.WriteFile(configPath, b, 0600); err != nil {
		return err
	}
	if out, err := capture(h.ctx, h.options.Proxy, "-validate", "-config", configPath); err != nil {
		return fmt.Errorf("proxy config invalid: %w: %s", err, out)
	}
	cmd := exec.Command(h.options.Proxy, "-config", configPath)
	cmd.WaitDelay = 5 * time.Second
	log := &lockedBuffer{}
	cmd.Stdout = io.MultiWriter(h.out, log)
	cmd.Stderr = io.MultiWriter(h.out, log)
	if err = cmd.Start(); err != nil {
		return err
	}
	h.proxy = cmd.Process
	h.proxyDone = make(chan error, 1)
	h.proxyLog = log
	go func() { h.proxyDone <- cmd.Wait() }()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		r, e := client.Get("http://" + h.httpAddr + "/healthz")
		if e == nil {
			r.Body.Close()
			if r.StatusCode == 200 {
				fmt.Fprintln(h.out, "✓ proxy ready")
				return nil
			}
		}
		select {
		case e := <-h.proxyDone:
			return fmt.Errorf("proxy exited: %v\n%s", e, log.String())
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("proxy did not become ready\n%s", log.String())
}

func (h *Harness) query(provider, engine, token, statement string) (string, error) {
	l, ok := h.listeners[provider+"-"+engine]
	if !ok {
		return "", errors.New("unknown profile")
	}
	username := "alice"
	if provider == "azure" || provider == "google" && engine == "postgres" {
		username = "alice@example.com"
	}
	if engine == "postgres" {
		host, port, _ := net.SplitHostPort(l.Addr)
		number, _ := strconv.Atoi(port)
		cfg, _ := pgconn.ParseConfig("sslmode=disable")
		cfg.Host = host
		cfg.Port = uint16(number)
		cfg.User = username
		cfg.Password = token
		cfg.Database = "testdb"
		cfg.TLSConfig = &tls.Config{InsecureSkipVerify: true}
		cfg.Fallbacks = nil
		conn, err := pgconn.ConnectConfig(h.ctx, cfg)
		if err != nil {
			return "", err
		}
		defer conn.Close(context.Background())
		result := conn.ExecParams(h.ctx, statement, nil, nil, nil, nil).Read()
		if result.Err != nil {
			return "", result.Err
		}
		if len(result.Rows) == 0 || len(result.Rows[0]) == 0 {
			return "", errors.New("query returned no row")
		}
		return string(result.Rows[0][0]), nil
	}
	cfg := mysqlDriver.NewConfig()
	cfg.User = username
	cfg.Passwd = token
	cfg.Net = "tcp"
	cfg.Addr = l.Addr
	cfg.DBName = "testdb"
	cfg.TLSConfig = "skip-verify"
	cfg.AllowCleartextPasswords = true
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return "", err
	}
	defer db.Close()
	var value string
	if err = db.QueryRowContext(h.ctx, statement).Scan(&value); err != nil {
		return "", err
	}
	return value, nil
}
