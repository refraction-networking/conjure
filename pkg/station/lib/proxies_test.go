//lint:file-ignore U1000 Ignore unused function temporarily for debugging
//go:build !race
// +build !race

package lib

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/refraction-networking/conjure/pkg/station/log"
)

// under construction - not finalized or definitive
// TODO: flesh out this test, or disable it. The go routines have a race condition that can result
// in the test being useless.
func TestProxyMockCovertReset(t *testing.T) {

	wg := new(sync.WaitGroup)

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
	go halfPipe(clientConn, covertConn, wg, logger, "Up "+"ABCDEF", &tunnelStats{proxyStats: getProxyStats()})
	go halfPipe(covertConn, clientConn, wg, logger, "Down "+"ABCDEF", &tunnelStats{proxyStats: getProxyStats()})

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
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestHalfpipeDeadlineEcho(t *testing.T) {
	// if os.Getenv("HALFPIPE") == "" {
	// 	t.Skip("Skipping slow tests involving halfpipe timeouts")
	// }

	clientClient, clientStation := net.Pipe()
	stationCovert, covertCovert := net.Pipe()

	logger := log.New(os.Stdout, "", 0)
	logger.SetLevel(log.TraceLevel)
	// log.SetLevel(log.TraceLevel)
	wg := sync.WaitGroup{}
	wg.Add(2)

	go halfPipe(clientStation, stationCovert, &wg, logger, "Up "+"XXXXXX", &tunnelStats{proxyStats: getProxyStats()})
	go halfPipe(stationCovert, clientStation, &wg, logger, "Down "+"XXXXXX", &tunnelStats{proxyStats: getProxyStats()})

	go func() {
		defer covertCovert.Close()
		_, _ = io.Copy(covertCovert, covertCovert)
	}()

	start := time.Now()
	for i := 0; i < 10; i++ {

		_, err := clientClient.Write([]byte(fmt.Sprintf("%d", i)))
		if err != nil {
			t.Fatalf("received '%v' at client", err)
		}

		b := make([]byte, 10)
		n, err := clientClient.Read(b)
		if errors.Is(err, io.EOF) {
			t.Fatalf("received EOF at client")
		} else if e, ok := err.(net.Error); ok && e.Timeout() {
			t.Fatalf("received Timeout at client")
		} else if err != nil {
			t.Fatalf("received '%v' at client", err)
		}

		t.Logf("%s, %d - %s", time.Since(start), n, string(b))

		time.Sleep(4 * time.Second)
	}

	clientClient.Close()
	wg.Wait()
}

func TestHalfpipeDeadlineUpload(t *testing.T) {
	if os.Getenv("HALFPIPE") == "" {
		t.Skip("Skipping slow tests involving halfpipe timeouts")
	}

	clientClient, clientStation := net.Pipe()
	stationCovert, covertCovert := net.Pipe()

	logger := log.New(os.Stdout, "", 0)
	logger.SetLevel(log.TraceLevel)
	wg := sync.WaitGroup{}
	wg.Add(2)

	go halfPipe(clientStation, stationCovert, &wg, logger, "Up "+"XXXXXX", &tunnelStats{proxyStats: getProxyStats()})
	go halfPipe(stationCovert, clientStation, &wg, logger, "Down "+"XXXXXX", &tunnelStats{proxyStats: getProxyStats()})

	go func() {
		defer covertCovert.Close()
		_, _ = io.Copy(io.Discard, covertCovert)
	}()

	start := time.Now()
	for i := 0; i < 10; i++ {

		n, err := clientClient.Write([]byte(fmt.Sprintf("%d", i)))
		if errors.Is(err, io.EOF) {
			t.Fatalf("received EOF at client")
		} else if e, ok := err.(net.Error); ok && e.Timeout() {
			t.Fatalf("received Timeout at client")
		} else if err != nil {
			t.Fatalf("received '%v' at client", err)
		}

		t.Logf("%s, %d %d", time.Since(start), n, i)

		time.Sleep(4 * time.Second)
	}

	clientClient.Close()
	covertCovert.Close()
	wg.Wait()
}

// Test that we actually timeout after one side (client) stalls too long.
func TestHalfpipeDeadlineActual(t *testing.T) {
	if os.Getenv("HALFPIPE") == "" {
		t.Skip("Skipping slow tests involving halfpipe timeouts")
	}

	clientClient, clientStation := net.Pipe()
	stationCovert, covertCovert := net.Pipe()

	logger := log.New(os.Stdout, "", 0)
	logger.SetLevel(log.TraceLevel)
	wg := sync.WaitGroup{}
	wg.Add(2)

	go halfPipe(clientStation, stationCovert, &wg, logger, "Up "+"XXXXXX", &tunnelStats{proxyStats: getProxyStats()})
	go halfPipe(stationCovert, clientStation, &wg, logger, "Down "+"XXXXXX", &tunnelStats{proxyStats: getProxyStats()})

	var serverErr error
	go func() {
		defer covertCovert.Close()
		for {
			b := make([]byte, 10)
			_, serverErr = covertCovert.Read(b)
			if serverErr != nil {
				return
			}
		}
	}()

	start := time.Now()
	for i := 0; i < 3; i++ {

		n, err := clientClient.Write([]byte(fmt.Sprintf("%d", i)))
		if errors.Is(err, io.EOF) {
			t.Fatalf("received EOF at client")
		} else if e, ok := err.(net.Error); ok && e.Timeout() {
			t.Fatalf("received Timeout at client")
		} else if err != nil {
			t.Fatalf("received '%v' at client", err)
		}

		t.Logf("%s, %d %d", time.Since(start), n, i)

		time.Sleep(4 * time.Second)
	}

	// sleep 27 + 4 = 31 > proxyStallTimeout
	time.Sleep(27 * time.Second)

	// covertStation will Timeout and send an EOF to covertCovert
	require.ErrorIs(t, io.EOF, serverErr)

	clientClient.Close()
	covertCovert.Close()
	wg.Wait()
}

// Test large writes and what happens when short write error is hit
func TestHalfpipeLargeWrite(t *testing.T) {

	inbuf := make([]byte, 32805)

	n, err := mrand.Read(inbuf)
	require.Nil(t, err)
	require.Equal(t, len(inbuf), n)

	clientClient, clientStation := net.Pipe()
	stationCovert, covertCovert := net.Pipe()

	logger := log.New(os.Stdout, "", 0)
	logger.SetLevel(log.TraceLevel)
	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() { io.Copy(io.Discard, covertCovert) }()

	go halfPipe(clientStation, stationCovert, &wg, logger, "Up "+"XXXXXX", &tunnelStats{proxyStats: getProxyStats()})
	go halfPipe(stationCovert, clientStation, &wg, logger, "Down "+"XXXXXX", &tunnelStats{proxyStats: getProxyStats()})

	nw, err := clientClient.Write(inbuf)
	require.Nil(t, err)

	require.Equal(t, len(inbuf), nw)

	clientClient.Close()
	covertCovert.Close()
	wg.Wait()
}

// Test basic wrapped halfpipe functionality
func TestProxyWrappersBasic(t *testing.T) {

	inbuf := make([]byte, 32805)
	outbuf := make([]byte, 32800)

	n, err := mrand.Read(inbuf)
	require.Nil(t, err)
	require.Equal(t, len(inbuf), n)

	clientClient, clientStation := net.Pipe()
	stationCovert, covertCovert := net.Pipe()
	defer clientClient.Close()
	defer covertCovert.Close()

	// log.SetLevel(log.TraceLevel)
	s := &tunnelStats{proxyStats: getProxyStats()}

	// wrap clientStation with a write wrapper - up is relatively arbitrary here
	wrappedClientStation := newRater(clientStation, s, nil, up)

	go func() { io.Copy(stationCovert, wrappedClientStation) }()
	go func() { io.Copy(clientStation, stationCovert) }()
	go func() { io.Copy(covertCovert, covertCovert) }()

	n, err = clientClient.Write([]byte("ABCDEF"))
	require.Nil(t, err)

	n1, err := clientClient.Read(outbuf)
	require.Nil(t, err)
	require.Equal(t, n, n1)

	require.Equal(t, n, int(s.BytesUp))

}
