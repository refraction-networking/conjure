package dtls

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var sharedSecret = []byte("hihihihihihihihihihihihihihihihi")

func TestSend(t *testing.T) {

	size := 65535
	toSend := make([]byte, size)

	_, err := rand.Read(toSend)
	require.Nil(t, err)

	server, client := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		s, err := Server(server, &Config{PSK: sharedSecret, SCTP: ServerAccept})
		require.Nil(t, err)
		defer s.Close()

		received := make([]byte, size)
		_, err = s.Read(received)
		require.Nil(t, err)

		require.Equal(t, toSend, received)
	}()

	c, err := Client(client, &Config{PSK: sharedSecret, SCTP: ClientOpen})
	require.Nil(t, err)
	defer c.Close()

	n, err := c.Write(toSend)
	require.Nil(t, err)
	require.Equal(t, len(toSend), n)

	wg.Wait()
}

func TestServerFail(t *testing.T) {

	ctxTime := 3 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), ctxTime)
	defer cancel()

	server, _ := net.Pipe()

	before := time.Now()
	_, err := ServerWithContext(ctx, server, &Config{PSK: sharedSecret, SCTP: ServerAccept})

	require.True(t, errors.Is(err, context.DeadlineExceeded))
	dur := time.Since(before)
	if dur > ctxTime*2 {
		t.Fatalf("Connect does not respect context")
	}
}

func TestClientFail(t *testing.T) {

	ctxTime := 3 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), ctxTime)
	defer cancel()

	_, client := net.Pipe()
	before := time.Now()
	_, err := ClientWithContext(ctx, client, &Config{PSK: sharedSecret, SCTP: ClientOpen})

	require.True(t, errors.Is(err, context.DeadlineExceeded))
	dur := time.Since(before)
	if dur > ctxTime*2 {
		t.Fatalf("Connect does not respect context")
	}
}

func passGoroutineLeak(testFunc func(*testing.T), t *testing.T) bool {
	initialGoroutines := runtime.NumGoroutine()

	testFunc(t)

	time.Sleep(2 * time.Second)

	return runtime.NumGoroutine() <= initialGoroutines
}

func TestGoroutineLeak(t *testing.T) {
	testFuncs := []func(*testing.T){TestSend, TestServerFail, TestClientFail}

	for _, test := range testFuncs {
		require.True(t, passGoroutineLeak(test, t))
	}

}
