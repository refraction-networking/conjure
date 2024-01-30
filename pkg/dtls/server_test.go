package dtls

import (
	"context"
	"crypto/rand"
	"fmt"
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

type mockConn struct {
	net.Conn
	waitTime time.Duration
}

func (c *mockConn) Write([]byte) (int, error) {
	time.Sleep(c.waitTime)
	return 0, fmt.Errorf("failed")
}

func TestClientRespectContext(t *testing.T) {
	_, client := net.Pipe()

	ctxTime := 3 * time.Second
	ctx, _ := context.WithTimeout(context.Background(), ctxTime)

	before := time.Now()
	_, err := ClientWithContext(ctx, client, &Config{PSK: sharedSecret, SCTP: ClientOpen})

	dur := time.Since(before)
	require.NotNil(t, err)

	if dur > ctxTime*2 {
		t.Fatalf("Connect does not respect context")
	}

}

func TestGoroutineLeak(t *testing.T) {
	initialGoroutines := runtime.NumGoroutine()

	TestSend(t)

	time.Sleep(2 * time.Second)

	require.LessOrEqual(t, runtime.NumGoroutine(), initialGoroutines)
}
