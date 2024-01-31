package dtls

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v2/pkg/protocol/handshake"
	"github.com/stretchr/testify/require"
)

type mockListener struct {
	inner net.Conn
	once  sync.Once
}

func (l *mockListener) Accept() (net.Conn, error) {
	var ret net.Conn
	l.once.Do(func() {
		ret = l.inner
	})
	if ret != nil {
		return ret, nil
	}
	return nil, fmt.Errorf("failed")
}

func (*mockListener) Close() error {
	return nil
}
func (*mockListener) Addr() net.Addr {
	return &net.IPAddr{IP: net.IP{1, 1, 1, 1}}
}

func TestListenSuccess(t *testing.T) {

	defaultCert, err := randomCertificate()
	require.Nil(t, err)

	size := 65535
	toSend := make([]byte, size)

	_, err = rand.Read(toSend)
	require.Nil(t, err)

	server, client := net.Pipe()

	var wg sync.WaitGroup
	wg.Add(1)

	ls := Listener{
		parent:      &mockListener{inner: server},
		connMap:     map[[handshake.RandomBytesLength]byte](chan net.Conn){},
		connToCert:  map[[handshake.RandomBytesLength]byte]*certPair{},
		defaultCert: defaultCert,
		closed:      make(chan struct{}),
		logAuthFail: func(*net.IP) {},
		logOther:    func(*net.IP) {},
	}
	go ls.acceptLoop()
	defer ls.Close()

	go func() {
		defer wg.Done()
		s, err := ls.Accept(&Config{PSK: sharedSecret, SCTP: ServerAccept})
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

func TestListenFail(t *testing.T) {

	defaultCert, err := randomCertificate()
	require.Nil(t, err)

	ctxTime := 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), ctxTime)
	defer cancel()

	server, _ := net.Pipe()

	ls := Listener{
		parent:      &mockListener{inner: server},
		connMap:     map[[handshake.RandomBytesLength]byte](chan net.Conn){},
		connToCert:  map[[handshake.RandomBytesLength]byte]*certPair{},
		defaultCert: defaultCert,
		closed:      make(chan struct{}),
		logAuthFail: func(*net.IP) {},
		logOther:    func(*net.IP) {},
	}
	go ls.acceptLoop()
	defer ls.Close()

	before := time.Now()
	_, err = ls.AcceptWithContext(ctx, &Config{PSK: sharedSecret, SCTP: ServerAccept})

	require.True(t, errors.Is(err, context.DeadlineExceeded))
	dur := time.Since(before)
	if dur > ctxTime*2 {
		t.Fatalf("Connect does not respect context")
	}
}
