package iamproxy

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// memBufferLimit bounds unread bytes per direction; writers block beyond it.
const memBufferLimit = 1 << 20

// memBuffer is one direction of an in-memory connection.
type memBuffer struct {
	mu            sync.Mutex
	data          []byte
	writeClosed   bool
	readClosed    bool
	changed       chan struct{}
	readDeadline  time.Time
	writeDeadline time.Time
}

func newMemBuffer() *memBuffer { return &memBuffer{changed: make(chan struct{})} }

// broadcast wakes every waiter; callers hold mu.
func (b *memBuffer) broadcast() {
	close(b.changed)
	b.changed = make(chan struct{})
}

// wait releases mu until the buffer changes or the deadline passes.
func (b *memBuffer) wait(deadline time.Time) error {
	ch := b.changed
	var timer <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return os.ErrDeadlineExceeded
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timer = t.C
	}
	b.mu.Unlock()
	defer b.mu.Lock()
	select {
	case <-ch:
		return nil
	case <-timer:
		return os.ErrDeadlineExceeded
	}
}

func expired(deadline time.Time) bool { return !deadline.IsZero() && !time.Now().Before(deadline) }

func (b *memBuffer) read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for {
		if b.readClosed {
			return 0, net.ErrClosed
		}
		if expired(b.readDeadline) {
			return 0, os.ErrDeadlineExceeded
		}
		if len(b.data) > 0 {
			n := copy(p, b.data)
			b.data = b.data[n:]
			b.broadcast()
			return n, nil
		}
		if b.writeClosed {
			return 0, io.EOF
		}
		if err := b.wait(b.readDeadline); err != nil {
			return 0, err
		}
	}
}

func (b *memBuffer) write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	written := 0
	for written < len(p) {
		if b.writeClosed {
			return written, net.ErrClosed
		}
		if b.readClosed {
			return written, io.ErrClosedPipe
		}
		if expired(b.writeDeadline) {
			return written, os.ErrDeadlineExceeded
		}
		if room := memBufferLimit - len(b.data); room > 0 {
			n := min(room, len(p)-written)
			b.data = append(b.data, p[written:written+n]...)
			written += n
			b.broadcast()
			continue
		}
		if err := b.wait(b.writeDeadline); err != nil {
			return written, err
		}
	}
	return written, nil
}

func (b *memBuffer) update(f func()) {
	b.mu.Lock()
	f()
	b.broadcast()
	b.mu.Unlock()
}

type memAddr string

func (memAddr) Network() string  { return "iamproxy-memory" }
func (a memAddr) String() string { return string(a) }

// memConn is a buffered, full-duplex in-memory net.Conn.
type memConn struct {
	in, out       *memBuffer
	local, remote memAddr
	closeOnce     sync.Once
}

func memPipe(clientAddr, serverAddr string) (client, server *memConn) {
	a, b := newMemBuffer(), newMemBuffer()
	return &memConn{in: a, out: b, local: memAddr(clientAddr), remote: memAddr(serverAddr)},
		&memConn{in: b, out: a, local: memAddr(serverAddr), remote: memAddr(clientAddr)}
}

func (c *memConn) Read(p []byte) (int, error)  { return c.in.read(p) }
func (c *memConn) Write(p []byte) (int, error) { return c.out.write(p) }
func (c *memConn) LocalAddr() net.Addr         { return c.local }
func (c *memConn) RemoteAddr() net.Addr        { return c.remote }

func (c *memConn) Close() error {
	c.closeOnce.Do(func() {
		c.in.update(func() { c.in.readClosed = true })
		c.out.update(func() { c.out.writeClosed = true })
	})
	return nil
}

func (c *memConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *memConn) SetReadDeadline(t time.Time) error {
	c.in.update(func() { c.in.readDeadline = t })
	return nil
}

func (c *memConn) SetWriteDeadline(t time.Time) error {
	c.out.update(func() { c.out.writeDeadline = t })
	return nil
}

// memListener hands in-memory connections to a listener's accept loop.
type memListener struct {
	addr      memAddr
	conns     chan net.Conn
	done      chan struct{}
	closeOnce sync.Once
}

func newMemListener(addr string) *memListener {
	return &memListener{addr: memAddr(addr), conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *memListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return nil
}

func (l *memListener) Addr() net.Addr { return l.addr }
