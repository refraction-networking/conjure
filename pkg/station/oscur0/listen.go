package oscur0

import (
	"fmt"
	"net"
	"sync"
)

const (
	cidSize    = 8
	listenPort = 41246
	receiveMTU = 8192
)

// NewTransport creates a new dtls transport
func ListenAndProxy(proxyFunc func(covert string, clientConn net.Conn), privKey []byte) error {
	addr := &net.UDPAddr{Port: listenPort}

	listener, err := Listen(addr, Config{PrivKey: privKey})
	if err != nil {
		return err
	}

	go func() {
		for {
			// Wait for a connection.
			conn, err := listener.Accept()
			if err != nil {
				fmt.Printf("error accepting connection: %v", err)
				continue
			}

			go proxyFunc(conn.Covert(), conn)

		}
	}()

	return nil
}

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
