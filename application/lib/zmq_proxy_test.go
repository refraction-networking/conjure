//go:build !race
// +build !race

package lib

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	zmq "github.com/pebbe/zmq4"
	"github.com/stretchr/testify/require"
)

const (
	numSockets        = 10
	messagesPerSocket = 10000
)

// This Test itself is a Data race issue, as the concurrent access to the
// subscribe socket is not safe. So I think his test indicates that ZMQProxy is
// now threadsafe through the use of channels (none of the messages get mangled
// and the process doesn't segfault). However, the test to fail when
// the `-race` flag is included because pebbe/zmq4 pubsub is not thread safe.
func TestConcurrentProxy(t *testing.T) {
	dir := t.TempDir()
	keyFilename := filepath.Join(dir, "test_key")
	keyFile, err := os.Create(keyFilename)
	require.Nil(t, err)

	// Generate sample Curve25519 key
	var key [32]byte
	_, err = io.ReadFull(rand.Reader, key[:])
	require.Nil(t, err)

	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	_, err = keyFile.Write(key[:])
	require.Nil(t, err)
	keyFile.Close()

	config := ZMQConfig{
		SocketName:        "test-proxying",
		ConnectSockets:    []socketConfig{},
		PrivateKeyPath:    keyFilename,
		HeartbeatInterval: 30000,
		HeartbeatTimeout:  30000,
	}

	sockets := make([]*zmq.Socket, numSockets)
	for i := 0; i < numSockets; i++ {
		name := fmt.Sprintf("ipc://@test-proxied-%d", i)
		config.ConnectSockets = append(config.ConnectSockets, socketConfig{
			Address:            name,
			AuthenticationType: "NULL",
			SubscriptionPrefix: "",
		})
		sockets[i], err = zmq.NewSocket(zmq.PUB)
		require.Nil(t, err)
		err = sockets[i].Bind(name)
		require.Nil(t, err)
	}

	zi := &ZMQIngester{
		ZMQConfig: &config,
	}
	go zi.proxyZMQ()

	sub, err := zmq.NewSocket(zmq.SUB)
	require.Nil(t, err)
	err = sub.SetSubscribe("")
	require.Nil(t, err)
	err = sub.Connect("ipc://@test-proxying")
	require.Nil(t, err)

	received := 0
	done := make(chan struct{})
	go func() {
		for {
			m, err := sub.RecvBytes(0)
			require.Nil(t, err)
			require.Equal(t, "test_test_test_test_test_test", string(m))

			received++
			if received == numSockets*messagesPerSocket {
				done <- struct{}{}
				return
			}
		}
	}()

	time.Sleep(1 * time.Second)

	for i := 0; i < numSockets; i++ {
		go func(sock *zmq.Socket) {
			for j := 0; j < messagesPerSocket; j++ {
				_, err = sock.SendBytes([]byte("test_test_test_test_test_test"), 0)
				if err != nil {
					panic(err)
				}
				time.Sleep(100 * time.Microsecond)
			}
		}(sockets[i])
		// Stagger messages; ZMQ seems to drop non-staggered messages,
		// and clumps of messages isn't our use-case
		time.Sleep(10 * time.Microsecond)
	}

	select {
	case <-time.After(10 * time.Second):
		t.Errorf("failed to receive correct number of messages; expected %d, got %d", numSockets*messagesPerSocket, received)
	case <-done:
		return
	}
}
