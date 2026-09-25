package iamproxy

import (
	"bytes"
	"io"
	"net"
	"testing"

	"golang.org/x/net/nettest"
)

func TestMemConnConformance(t *testing.T) {
	nettest.TestConn(t, func() (net.Conn, net.Conn, func(), error) {
		a, b := memPipe("a", "b")
		return a, b, func() { a.Close(); b.Close() }, nil
	})
}

func TestMemConnLargeWriteBlocksUntilRead(t *testing.T) {
	a, b := memPipe("a", "b")
	defer a.Close()
	payload := bytes.Repeat([]byte("x"), 3*memBufferLimit+17)
	go func() { _, _ = a.Write(payload); _ = a.Close() }()
	got, err := io.ReadAll(b)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("read %d bytes, err %v", len(got), err)
	}
}
