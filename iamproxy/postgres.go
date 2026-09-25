package iamproxy

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func pgWrite(c net.Conn, typ byte, body []byte) error {
	b := make([]byte, 5+len(body))
	b[0] = typ
	binary.BigEndian.PutUint32(b[1:], uint32(4+len(body)))
	copy(b[5:], body)
	_, err := c.Write(b)
	return err
}

func pgFatal(c net.Conn, code, msg string) {
	body := []byte("SFATAL\x00C" + code + "\x00M" + msg + "\x00\x00")
	_ = pgWrite(c, 'E', body)
}

func pgStartup(c net.Conn) (map[string]string, error) {
	for {
		var head [8]byte
		if _, err := io.ReadFull(c, head[:]); err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(head[:4])
		code := binary.BigEndian.Uint32(head[4:])
		if n < 8 || n > 1<<20 {
			return nil, errors.New("invalid startup length")
		}
		if code == 80877104 {
			if n != 8 {
				return nil, errors.New("invalid GSS request")
			}
			_, err := c.Write([]byte{'N'})
			if err != nil {
				return nil, err
			}
			continue
		}
		if code == 80877102 {
			if n != 16 {
				return nil, errors.New("invalid cancel length")
			}
			var key [8]byte
			if _, err := io.ReadFull(c, key[:]); err != nil {
				return nil, err
			}
			return map[string]string{"_cancel": string(key[:])}, nil
		}
		if code == 80877103 {
			return map[string]string{"_ssl": "1"}, nil
		}
		if code != 196608 {
			return nil, errors.New("unsupported protocol version")
		}
		b := make([]byte, n-8)
		if _, err := io.ReadFull(c, b); err != nil {
			return nil, err
		}
		if len(b) == 0 || b[len(b)-1] != 0 {
			return nil, errors.New("invalid startup parameters")
		}
		fields := strings.Split(string(b[:len(b)-1]), "\x00")
		if fields[len(fields)-1] == "" {
			fields = fields[:len(fields)-1]
		}
		if len(fields)%2 != 0 {
			return nil, errors.New("invalid startup parameters")
		}
		m := map[string]string{}
		for i := 0; i < len(fields); i += 2 {
			if fields[i] == "" {
				return nil, errors.New("empty parameter")
			}
			m[fields[i]] = fields[i+1]
		}
		return m, nil
	}
}

func pgPassword(c net.Conn) (string, error) {
	var head [5]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", err
	}
	if head[0] != 'p' {
		return "", errors.New("expected password message")
	}
	n := binary.BigEndian.Uint32(head[1:])
	if n < 5 || n > 1<<20 {
		return "", errors.New("invalid password length")
	}
	b := make([]byte, n-4)
	if _, err := io.ReadFull(c, b); err != nil {
		return "", err
	}
	if b[len(b)-1] != 0 {
		return "", errors.New("unterminated password")
	}
	return string(b[:len(b)-1]), nil
}

type pgCancelTarget struct{ upstream string }

func (e *Emulator) servePostgres(ctx context.Context, conn net.Conn, l Listener) error {
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	params, err := pgStartup(conn)
	if err != nil {
		return err
	}
	if raw, ok := params["_cancel"]; ok {
		return e.pgCancel(ctx, l, []byte(raw))
	}
	if params["_ssl"] != "1" {
		pgFatal(conn, "08004", "TLS is required")
		return errors.New("TLS required")
	}
	if _, err = conn.Write([]byte{'S'}); err != nil {
		return err
	}
	tlsConn := tls.Server(conn, e.tls)
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	conn = tlsConn
	params, err = pgStartup(conn)
	if err != nil {
		return err
	}
	// libpq 17+ and pgx send CancelRequest over TLS when the session used it.
	if raw, ok := params["_cancel"]; ok {
		return e.pgCancel(ctx, l, []byte(raw))
	}
	if params["_ssl"] != "" {
		return errors.New("invalid startup after TLS")
	}
	username := params["user"]
	if username == "" {
		pgFatal(conn, "28000", "user required")
		return errors.New("user required")
	}
	var request [4]byte
	binary.BigEndian.PutUint32(request[:], 3)
	if err = pgWrite(conn, 'R', request[:]); err != nil {
		return err
	}
	password, err := pgPassword(conn)
	if err != nil {
		return err
	}
	p, err := e.svc.Validate(l, username, password)
	if err != nil {
		pgFatal(conn, "28P01", "authentication failed")
		return err
	}
	host, portStr, err := net.SplitHostPort(l.Upstream)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("invalid upstream port")
	}
	pcfg, err := pgconn.ParseConfig("sslmode=disable")
	if err != nil {
		return err
	}
	pcfg.Host = host
	pcfg.Port = uint16(port)
	pcfg.User = p.BackendUser
	pcfg.Password = p.BackendPassword
	pcfg.Database = params["database"]
	if pcfg.Database == "" {
		pcfg.Database = p.BackendUser
	}
	pcfg.ConnectTimeout = 8 * time.Second
	pcfg.Fallbacks = nil
	// The configured upstream goes to the dialer unresolved, so a custom
	// dialer can own name resolution.
	pcfg.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
	pcfg.DialFunc = pgconn.DialFunc(e.dial)
	if l.UpstreamTLS != "" && l.UpstreamTLS != "disable" {
		pcfg.TLSConfig = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: l.UpstreamTLS == "require"}
	}
	if v := params["application_name"]; v != "" {
		pcfg.RuntimeParams["application_name"] = v
	}
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	backend, err := pgconn.ConnectConfig(connectCtx, pcfg)
	if err != nil {
		pgFatal(conn, "08006", "backend connection failed")
		return fmt.Errorf("backend connection failed")
	}
	if err = backend.SyncConn(connectCtx); err != nil {
		_ = backend.Close(context.Background())
		return err
	}
	hijacked, err := backend.Hijack()
	if err != nil {
		_ = backend.Close(context.Background())
		return err
	}
	defer hijacked.Conn.Close()
	if err = pgWrite(conn, 'R', []byte{0, 0, 0, 0}); err != nil {
		return err
	}
	keys := make([]string, 0, len(hijacked.ParameterStatuses))
	for k := range hijacked.ParameterStatuses {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err = pgWrite(conn, 'S', []byte(k+"\x00"+hijacked.ParameterStatuses[k]+"\x00")); err != nil {
			return err
		}
	}
	if len(hijacked.SecretKey) != 4 {
		return errors.New("invalid backend secret key")
	}
	var keyData [8]byte
	binary.BigEndian.PutUint32(keyData[:4], hijacked.PID)
	copy(keyData[4:], hijacked.SecretKey)
	if err = pgWrite(conn, 'K', keyData[:]); err != nil {
		return err
	}
	if err = pgWrite(conn, 'Z', []byte{hijacked.TxStatus}); err != nil {
		return err
	}
	cancelKey := string(keyData[:])
	e.cancels.Store(l.Name+cancelKey, pgCancelTarget{l.Upstream})
	defer e.cancels.Delete(l.Name + cancelKey)
	_ = conn.SetDeadline(time.Time{})
	relay(conn, hijacked.Conn)
	return nil
}

func (e *Emulator) pgCancel(ctx context.Context, l Listener, raw []byte) error {
	if len(raw) != 8 {
		return errors.New("invalid cancel")
	}
	var msg [16]byte
	binary.BigEndian.PutUint32(msg[:4], 16)
	binary.BigEndian.PutUint32(msg[4:8], 80877102)
	copy(msg[8:], raw)
	target, ok := e.cancels.Load(l.Name + string(raw))
	if !ok {
		return nil
	}
	dialCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c, err := e.dial(dialCtx, "tcp", target.(pgCancelTarget).upstream)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write(msg[:])
	return err
}
