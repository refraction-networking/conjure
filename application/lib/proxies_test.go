//lint:file-ignore U1000 Ignore unused function temporarily for debugging
//go:build !race
// +build !race

package lib

import (
	"bytes"
	"errors"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/refraction-networking/conjure/application/log"
)

var errNotExist = errors.New("not implemented")

// under construction - not finalized or definitive
func TestProxyMockCovertReset(t *testing.T) {

	wg := new(sync.WaitGroup)
	oncePrintErr := new(sync.Once)

	logger := log.New(os.Stdout, "", 0)
	logger.SetLevel(log.TraceLevel)

	var buf bytes.Buffer
	clientConn := &mockConn{
		read: func(b []byte) (n int, err error) {
			return 3, net.ErrClosed
		},
		write: func(b []byte) (n int, err error) {
			buf.Write(b)
			return len(b), nil
		},
		close: func() error {
			return syscall.ECONNRESET
		},
	}

	covertConn := &mockConn{
		read: func(b []byte) (n int, err error) {
			return buf.Read(b)
		},
		write: func(b []byte) (n int, err error) {
			buf.Write(b)
			return len(b), nil
		},
		isClosed: false,
		close: func() error {
			return nil
		},
	}

	wg.Add(2)
	go halfPipe(clientConn, covertConn, wg, oncePrintErr, logger, "Up "+"ABCDEF")
	go halfPipe(covertConn, clientConn, wg, oncePrintErr, logger, "Down "+"ABCDEF")

	wg.Wait()
}

type mockConn struct {
	buf      bytes.Buffer
	isClosed bool

	read  func(b []byte) (n int, err error)
	write func(b []byte) (n int, err error)
	close func() error
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.read == nil {
		return 0, errNotExist
	}
	return m.read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.write == nil {
		return 0, errNotExist
	}
	return m.write(b)
}

// Close closes the connection.
func (m *mockConn) Close() error {
	if m.close == nil {
		return errNotExist
	}
	return m.close()
}

// LocalAddr -
func (m *mockConn) LocalAddr() net.Addr {
	return nil
}

func (m *mockConn) RemoteAddr() net.Addr {
	return nil
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return errNotExist
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return errNotExist
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return errNotExist
}
