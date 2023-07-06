package dtls

import (
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var sharedSecret = []byte("hihihihihihihihihihihihihihihihi")

func TestSend(t *testing.T) {
	size := 65535
	toSend := make([]byte, size)

	rand.Read(toSend)

	server, client := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		s, err := Server(server, &Config{PSK: sharedSecret, SCTP: ServerAccept})
		require.Nil(t, err)

		received := make([]byte, size)
		_, err = s.Read(received)
		require.Nil(t, err)

		require.Equal(t, toSend, received)
	}()

	time.Sleep(1 * time.Second)

	c, err := Client(client, &Config{PSK: sharedSecret, SCTP: ClientOpen})
	require.Nil(t, err)

	n, err := c.Write(toSend)
	require.Nil(t, err)
	require.Equal(t, len(toSend), n)

	wg.Wait()
}
