package dtls

import (
	"crypto/rand"
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

func TestGoroutineLeak(t *testing.T) {
	initialGoroutines := runtime.NumGoroutine()

	TestSend(t)

	time.Sleep(2 * time.Second)

	require.LessOrEqual(t, runtime.NumGoroutine(), initialGoroutines)
}
