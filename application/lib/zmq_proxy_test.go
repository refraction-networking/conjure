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
)

const (
	numSockets        = 10
	messagesPerSocket = 10000
)

func TestConcurrentProxy(t *testing.T) {
	dir := t.TempDir()
	keyFilename := filepath.Join(dir, "test_key")
	keyFile, err := os.Create(keyFilename)
	if err != nil {
		panic(err)
	}
	// Generate sample Curve25519 key
	var key [32]byte
	_, err = io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	_, err = keyFile.Write(key[:])
	if err != nil {
		panic(err)
	}
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
		if err != nil {
			panic(err)
		}
		err = sockets[i].Bind(name)
		if err != nil {
			panic(err)
		}
	}

	go ZMQProxy(config)

	sub, err := zmq.NewSocket(zmq.SUB)
	if err != nil {
		panic(err)
	}
	sub.SetSubscribe("")
	err = sub.Connect("ipc://@test-proxying")
	if err != nil {
		panic(err)
	}

	received := 0
	done := make(chan struct{})
	go func() {
		for {
			_, err := sub.RecvBytes(0)
			if err != nil {
				panic(err)
			}
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
				_, err = sock.SendBytes([]byte("test"), 0)
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
