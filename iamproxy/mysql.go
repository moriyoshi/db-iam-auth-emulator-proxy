package iamproxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
)

func myRead(c net.Conn) ([]byte, byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, 0, err
	}
	n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
	if n > 1<<20 {
		return nil, 0, errors.New("MySQL packet too large")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(c, b)
	return b, h[3], err
}

func myWrite(c net.Conn, seq byte, b []byte) error {
	if len(b) > 1<<20 {
		return errors.New("MySQL packet too large")
	}
	h := []byte{byte(len(b)), byte(len(b) >> 8), byte(len(b) >> 16), seq}
	if _, err := c.Write(h); err != nil {
		return err
	}
	_, err := c.Write(b)
	return err
}

func myError(c net.Conn, seq byte, code uint16, msg string) {
	b := []byte{0xff, byte(code), byte(code >> 8), '#', '2', '8', '0', '0', '0'}
	b = append(b, msg...)
	_ = myWrite(c, seq, b)
}

func myCString(b []byte) (string, []byte, error) {
	i := 0
	for i < len(b) && b[i] != 0 {
		i++
	}
	if i == len(b) {
		return "", nil, errors.New("unterminated MySQL string")
	}
	return string(b[:i]), b[i+1:], nil
}

func myLenenc(b []byte) (int, []byte, error) {
	if len(b) == 0 {
		return 0, nil, errors.New("empty length")
	}
	switch b[0] {
	case 0xfc:
		if len(b) < 3 {
			return 0, nil, errors.New("short length")
		}
		return int(binary.LittleEndian.Uint16(b[1:])), b[3:], nil
	case 0xfd:
		if len(b) < 4 {
			return 0, nil, errors.New("short length")
		}
		return int(b[1]) | int(b[2])<<8 | int(b[3])<<16, b[4:], nil
	case 0xfe:
		if len(b) < 9 {
			return 0, nil, errors.New("short length")
		}
		n := binary.LittleEndian.Uint64(b[1:])
		if n > 1<<20 {
			return 0, nil, errors.New("oversized length")
		}
		return int(n), b[9:], nil
	default:
		return int(b[0]), b[1:], nil
	}
}

func myHandshakeResponse(b []byte) (uint32, string, string, string, error) {
	if len(b) < 33 {
		return 0, "", "", "", errors.New("short handshake")
	}
	cap := binary.LittleEndian.Uint32(b[:4])
	if cap&mysql.CLIENT_PROTOCOL_41 == 0 || cap&mysql.CLIENT_PLUGIN_AUTH == 0 {
		return 0, "", "", "", errors.New("unsupported client")
	}
	rest := b[32:]
	username, next, err := myCString(rest)
	if err != nil {
		return 0, "", "", "", err
	}
	rest = next
	var n int
	if cap&mysql.CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
		n, rest, err = myLenenc(rest)
		if err != nil {
			return 0, "", "", "", err
		}
	} else if cap&mysql.CLIENT_SECURE_CONNECTION != 0 {
		if len(rest) < 1 {
			return 0, "", "", "", errors.New("missing password length")
		}
		n = int(rest[0])
		rest = rest[1:]
	} else {
		var password string
		password, rest, err = myCString(rest)
		if err != nil {
			return 0, "", "", "", err
		}
		n = len(password)
		rest = append([]byte(password), rest...)
	}
	if n < 0 || n > len(rest) {
		return 0, "", "", "", errors.New("invalid password length")
	}
	password := string(rest[:n])
	if !strings.HasSuffix(password, "\x00") || strings.Contains(password[:len(password)-1], "\x00") {
		return 0, "", "", "", errors.New("invalid cleartext password")
	}
	password = strings.TrimSuffix(password, "\x00")
	rest = rest[n:]
	database := ""
	if cap&mysql.CLIENT_CONNECT_WITH_DB != 0 {
		database, rest, err = myCString(rest)
		if err != nil {
			return 0, "", "", "", err
		}
	}
	if cap&mysql.CLIENT_PLUGIN_AUTH != 0 {
		var plugin string
		plugin, _, err = myCString(rest)
		if err != nil {
			return 0, "", "", "", err
		}
		if plugin != "mysql_clear_password" {
			return 0, "", "", "", errors.New("cleartext plugin required")
		}
	}
	return cap, username, password, database, nil
}

func (e *Emulator) serveMySQL(ctx context.Context, conn net.Conn, l Listener) error {
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	var salt [20]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return err
	}
	cap := uint32(mysql.CLIENT_LONG_PASSWORD | mysql.CLIENT_LONG_FLAG | mysql.CLIENT_CONNECT_WITH_DB | mysql.CLIENT_PROTOCOL_41 | mysql.CLIENT_SSL | mysql.CLIENT_TRANSACTIONS | mysql.CLIENT_SECURE_CONNECTION | mysql.CLIENT_MULTI_RESULTS | mysql.CLIENT_PS_MULTI_RESULTS | mysql.CLIENT_PLUGIN_AUTH | mysql.CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA | mysql.CLIENT_SESSION_TRACK | mysql.CLIENT_DEPRECATE_EOF | mysql.CLIENT_QUERY_ATTRIBUTES)
	greeting := []byte{10}
	greeting = append(greeting, []byte("8.0.36-iam-proxy")...)
	greeting = append(greeting, 0)
	greeting = binary.LittleEndian.AppendUint32(greeting, 1)
	greeting = append(greeting, salt[:8]...)
	greeting = append(greeting, 0)
	greeting = binary.LittleEndian.AppendUint16(greeting, uint16(cap))
	greeting = append(greeting, 45)
	greeting = binary.LittleEndian.AppendUint16(greeting, 2)
	greeting = binary.LittleEndian.AppendUint16(greeting, uint16(cap>>16))
	greeting = append(greeting, 21)
	greeting = append(greeting, make([]byte, 10)...)
	greeting = append(greeting, salt[8:]...)
	greeting = append(greeting, 0)
	greeting = append(greeting, []byte("mysql_clear_password\x00")...)
	if err := myWrite(conn, 0, greeting); err != nil {
		return err
	}
	resp, seq, err := myRead(conn)
	if err != nil {
		return err
	}
	if seq != 1 || len(resp) != 32 || binary.LittleEndian.Uint32(resp[:4])&mysql.CLIENT_SSL == 0 {
		myError(conn, 2, 1045, "TLS is required")
		return errors.New("TLS required")
	}
	tlsConn := tls.Server(conn, e.tls)
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	conn = tlsConn
	resp, seq, err = myRead(conn)
	if err != nil {
		return err
	}
	if seq != 2 {
		return errors.New("bad MySQL handshake sequence")
	}
	clientCap, username, password, database, err := myHandshakeResponse(resp)
	if err != nil {
		myError(conn, 3, 1045, "unsupported authentication")
		return err
	}
	p, err := e.svc.Validate(l, username, password)
	if err != nil {
		myError(conn, 3, 1045, "authentication failed")
		return err
	}
	backendOptions := []client.Option{func(c *client.Conn) error {
		for _, flag := range myFramingCaps {
			if clientCap&flag == 0 {
				c.UnsetCapability(flag)
			} else {
				if flag != mysql.CLIENT_DEPRECATE_EOF && flag != mysql.CLIENT_QUERY_ATTRIBUTES {
					_ = c.SetCapability(flag)
				}
			}
		}
		return nil
	}}
	if l.UpstreamTLS != "" && l.UpstreamTLS != "disable" {
		host, _, _ := net.SplitHostPort(l.Upstream)
		backendOptions = append(backendOptions, func(c *client.Conn) error {
			c.SetTLSConfig(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: l.UpstreamTLS == "require"})
			return nil
		})
	}
	connectCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	backend, err := client.ConnectWithDialer(connectCtx, "tcp", l.Upstream, p.BackendUser, p.BackendPassword, database, client.Dialer(e.dial), backendOptions...)
	if err != nil {
		myError(conn, 3, 1045, "backend connection failed")
		return fmt.Errorf("backend connection failed")
	}
	defer backend.Close()
	// Relayed bytes are only valid if both sides framed results the same way.
	frontCap, backCap := clientCap&cap, myNegotiated(backend)
	for _, flag := range myFramingCaps {
		if frontCap&flag != backCap&flag {
			myError(conn, 3, 1235, "backend does not support the negotiated client capabilities")
			return fmt.Errorf("backend capability mismatch: %s", mysql.CapNames[flag])
		}
	}
	// OK header, affected rows, last insert id, autocommit status, warnings.
	if err = myWrite(conn, 3, []byte{0, 0, 0, 2, 0, 0, 0}); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	myRelay(conn, backend.Conn.Conn)
	return nil
}

// myFramingCaps change how packets after login are laid out.
var myFramingCaps = []uint32{mysql.CLIENT_MULTI_RESULTS, mysql.CLIENT_PS_MULTI_RESULTS, mysql.CLIENT_SESSION_TRACK, mysql.CLIENT_DEPRECATE_EOF, mysql.CLIENT_QUERY_ATTRIBUTES}

// myNegotiated decodes the capabilities a go-mysql connection agreed on,
// which the client exposes only as flag names.
func myNegotiated(c *client.Conn) uint32 {
	var caps uint32
	for _, name := range strings.Split(c.CapabilityString(), "|") {
		for flag, n := range mysql.CapNames {
			if n == name {
				caps |= flag
			}
		}
	}
	return caps
}

func myRelay(front, back net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(front, back); done <- struct{}{} }()
	go func() {
		for {
			var h [4]byte
			if _, err := io.ReadFull(front, h[:]); err != nil {
				break
			}
			n := int(h[0]) | int(h[1])<<8 | int(h[2])<<16
			if n > 1<<24-1 {
				break
			}
			b := make([]byte, n)
			if _, err := io.ReadFull(front, b); err != nil {
				break
			}
			if h[3] == 0 && n > 0 && b[0] == 0x11 {
				myError(front, 1, 1045, "change user is unsupported")
				continue
			}
			if _, err := back.Write(h[:]); err != nil {
				break
			}
			if _, err := back.Write(b); err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done
	_ = front.Close()
	_ = back.Close()
	<-done
}
