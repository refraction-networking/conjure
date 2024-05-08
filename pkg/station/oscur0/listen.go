package oscur0

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
	dtlsnet "github.com/pion/dtls/v2/pkg/net"
	"github.com/refraction-networking/conjure/pkg/station/lib"
)

const (
	cidSize    = 8
	listenPort = 41246
	receiveMTU = 8192
)

// NewTransport creates a new dtls transport
func ListenAndProxy(proxyFunc func(covert string, clientConn net.Conn), privKey [lib.PrivateKeyLength]byte) error {
	addr := &net.UDPAddr{Port: listenPort}

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		ConnectionIDGenerator: dtls.RandomCIDGenerator(cidSize),
	}

	// Connect to a DTLS server
	listener, err := dtls.NewResumeListener("udp", addr, config)
	if err != nil {
		return err
	}

	go func() {
		for {
			// Wait for a connection.
			pconn, addr, err := listener.Accept()
			if err != nil {
				continue
			}

			ctxtimout, _ := context.WithTimeout(context.Background(), 10*time.Second)

			kcpConn, info, err := ServerWithContext(ctxtimout, pconn, addr, Config{privKey: privKey})
			if err != nil {
				continue
			}

			go proxyFunc(info.GetCovert(), kcpConn)

		}
	}()

	return nil
}

type Listener struct {
	inner  dtlsnet.PacketListener
	config Config
}

// func (l *Listener) Accept() (net.Conn, error) {
// 	pconn, raddr, err := l.inner.Accept()
// 	if err != nil {
// 		return nil, err
// 	}

// 	return Server(pconn, raddr, l.config)
// }

type edit1pconn struct {
	net.PacketConn
	onceBytes []byte
	remote    net.Addr
	doOnce    sync.Once
}

func (c *edit1pconn) ReadFrom(p []byte) (int, net.Addr, error) {
	var copied int
	c.doOnce.Do(func() {
		copied = copy(p, c.onceBytes)
	})
	if copied > 0 {
		return copied, c.remote, nil
	}

	return c.PacketConn.ReadFrom(p)
}

type edit1conn struct {
	net.Conn
	onceBytes []byte
	doOnce    sync.Once
}

func (c *edit1conn) Read(p []byte) (n int, err error) {
	var copied int
	c.doOnce.Do(func() {
		copied = copy(p, c.onceBytes)
	})
	if copied > 0 {
		return copied, nil
	}

	return c.Conn.Read(p)
}
