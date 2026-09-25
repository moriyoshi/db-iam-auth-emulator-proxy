// Package fakedb provides minimal PostgreSQL and MySQL upstream servers for
// hermetic tests. They accept one backend account and answer every query
// with the logged-in user name in MySQL's current_user() format for MySQL.
package fakedb

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"io"
	"net"
	"sync"

	"github.com/jackc/pgx/v5/pgproto3"
)

// Server records upstream connections for assertions.
type Server struct {
	User, Password string
	// NoDeprecateEOF makes the MySQL fake frame results with EOF packets,
	// like servers older than MySQL 5.7.5.
	NoDeprecateEOF bool

	mu      sync.Mutex
	dials   []string
	params  []map[string]string
	cancels []uint32
}

// Dials returns every address the emulator asked this upstream to dial.
func (s *Server) Dials() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.dials...)
}

// Startups returns the startup parameters of accepted logins.
func (s *Server) Startups() []map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]string(nil), s.params...)
}

// Cancels returns backend process IDs named by PostgreSQL cancel requests
// that carried the right secret.
func (s *Server) Cancels() []uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint32(nil), s.cancels...)
}

// PostgresDialer serves a fake PostgreSQL backend over each dialed pipe.
func (s *Server) PostgresDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.dial(addr, s.servePostgres)
}

// MySQLDialer serves a fake MySQL backend over each dialed pipe.
func (s *Server) MySQLDialer(ctx context.Context, network, addr string) (net.Conn, error) {
	return s.dial(addr, s.serveMySQL)
}

func (s *Server) dial(addr string, serve func(net.Conn)) (net.Conn, error) {
	s.mu.Lock()
	s.dials = append(s.dials, addr)
	s.mu.Unlock()
	client, backend := net.Pipe()
	go func() {
		defer backend.Close()
		serve(backend)
	}()
	return client, nil
}

const pgPID, pgSecret = 4242, "k3y!"

func (s *Server) servePostgres(conn net.Conn) {
	b := pgproto3.NewBackend(conn, conn)
	msg, err := b.ReceiveStartupMessage()
	if err != nil {
		return
	}
	switch m := msg.(type) {
	case *pgproto3.CancelRequest:
		if m.ProcessID == pgPID && string(m.SecretKey) == pgSecret {
			s.mu.Lock()
			s.cancels = append(s.cancels, m.ProcessID)
			s.mu.Unlock()
		}
		return
	case *pgproto3.StartupMessage:
		b.Send(&pgproto3.AuthenticationCleartextPassword{})
		if b.Flush() != nil || b.SetAuthType(pgproto3.AuthTypeCleartextPassword) != nil {
			return
		}
		pw, err := b.Receive()
		if err != nil {
			return
		}
		if p, ok := pw.(*pgproto3.PasswordMessage); !ok || m.Parameters["user"] != s.User || p.Password != s.Password {
			b.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "28P01", Message: "password authentication failed"})
			_ = b.Flush()
			return
		}
		s.mu.Lock()
		s.params = append(s.params, m.Parameters)
		s.mu.Unlock()
		b.Send(&pgproto3.AuthenticationOk{})
		b.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "17.0"})
		b.Send(&pgproto3.BackendKeyData{ProcessID: pgPID, SecretKey: []byte(pgSecret)})
		b.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		if b.Flush() != nil {
			return
		}
		for {
			msg, err := b.Receive()
			if err != nil {
				return
			}
			switch msg.(type) {
			case *pgproto3.Query:
				b.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("current_user"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}}})
				b.Send(&pgproto3.DataRow{Values: [][]byte{[]byte(s.User)}})
				b.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
				b.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				if b.Flush() != nil {
					return
				}
			case *pgproto3.Terminate:
				return
			}
		}
	}
}

const (
	myProtocol41     = 1 << 9
	mySecureConn     = 1 << 15
	myLongPassword   = 1
	myLongFlag       = 1 << 2
	myConnectWithDB  = 1 << 3
	myTransactions   = 1 << 13
	myMultiResults   = 1 << 17
	myPluginAuth     = 1 << 19
	myPluginLenenc   = 1 << 21
	myDeprecateEOF   = 1 << 24
	myStatusAutocomm = 2
)

func (s *Server) serveMySQL(conn net.Conn) {
	caps := uint32(myProtocol41 | mySecureConn | myLongPassword | myLongFlag | myConnectWithDB | myTransactions | myMultiResults | myPluginAuth | myPluginLenenc)
	if !s.NoDeprecateEOF {
		caps |= myDeprecateEOF
	}
	salt := []byte("abcdefghij0123456789")
	g := []byte{10}
	g = append(g, "8.0.0-fake\x00"...)
	g = binary.LittleEndian.AppendUint32(g, 7)
	g = append(g, salt[:8]...)
	g = append(g, 0)
	g = binary.LittleEndian.AppendUint16(g, uint16(caps))
	g = append(g, 45)
	g = binary.LittleEndian.AppendUint16(g, myStatusAutocomm)
	g = binary.LittleEndian.AppendUint16(g, uint16(caps>>16))
	g = append(g, 21)
	g = append(g, make([]byte, 10)...)
	g = append(g, salt[8:]...)
	g = append(g, 0)
	g = append(g, "mysql_native_password\x00"...)
	if myWrite(conn, 0, g) != nil {
		return
	}
	resp, _, err := myRead(conn)
	if err != nil || len(resp) < 32 {
		return
	}
	caps &= binary.LittleEndian.Uint32(resp)
	rest := resp[32:]
	user, rest, _ := bytes.Cut(rest, []byte{0})
	var auth []byte
	if len(rest) > 0 {
		n := int(rest[0])
		if n+1 <= len(rest) {
			auth, rest = rest[1:1+n], rest[1+n:]
		}
	}
	db, _, _ := bytes.Cut(rest, []byte{0})
	if string(user) != s.User || !bytes.Equal(auth, nativeScramble(salt, s.Password)) {
		_ = myWrite(conn, 2, append([]byte{0xff, 0x15, 0x04, '#'}, "28000Access denied"...))
		return
	}
	s.mu.Lock()
	s.params = append(s.params, map[string]string{"user": string(user), "database": string(db)})
	s.mu.Unlock()
	if myWrite(conn, 2, myOK(0)) != nil {
		return
	}
	for {
		cmd, _, err := myRead(conn)
		if err != nil || len(cmd) == 0 || cmd[0] == 0x01 {
			return
		}
		switch cmd[0] {
		case 0x03: // COM_QUERY
			col := []byte{}
			for _, v := range []string{"def", "", "", "", "current_user()", ""} {
				col = append(col, byte(len(v)))
				col = append(col, v...)
			}
			col = append(col, 0x0c, 33, 0, 0, 1, 0, 0, 0xfd, 0, 0, 0, 0, 0)
			packets := [][]byte{{1}, col}
			if caps&myDeprecateEOF == 0 {
				packets = append(packets, []byte{0xfe, 0, 0, myStatusAutocomm, 0})
			}
			row := s.User + "@%"
			packets = append(packets, append([]byte{byte(len(row))}, row...))
			if caps&myDeprecateEOF == 0 {
				packets = append(packets, []byte{0xfe, 0, 0, myStatusAutocomm, 0})
			} else {
				packets = append(packets, myOK(0xfe))
			}
			for i, p := range packets {
				if myWrite(conn, byte(i+1), p) != nil {
					return
				}
			}
		case 0x0e, 0x02: // COM_PING, COM_INIT_DB
			if myWrite(conn, 1, myOK(0)) != nil {
				return
			}
		default:
			if myWrite(conn, 1, append([]byte{0xff, 0x2f, 0x04, '#'}, "HY000unsupported"...)) != nil {
				return
			}
		}
	}
}

func myOK(header byte) []byte { return []byte{header, 0, 0, myStatusAutocomm, 0, 0, 0} }

func nativeScramble(salt []byte, password string) []byte {
	a := sha1.Sum([]byte(password))
	b := sha1.Sum(a[:])
	c := sha1.Sum(append(append([]byte{}, salt...), b[:]...))
	for i := range a {
		a[i] ^= c[i]
	}
	return a[:]
}

func myRead(c net.Conn) ([]byte, byte, error) {
	var h [4]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return nil, 0, err
	}
	b := make([]byte, int(h[0])|int(h[1])<<8|int(h[2])<<16)
	_, err := io.ReadFull(c, b)
	return b, h[3], err
}

func myWrite(c net.Conn, seq byte, b []byte) error {
	_, err := c.Write(append([]byte{byte(len(b)), byte(len(b) >> 8), byte(len(b) >> 16), seq}, b...))
	return err
}
