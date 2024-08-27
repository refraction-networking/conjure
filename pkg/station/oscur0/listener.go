package oscur0

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/pion/dtls/v2"
	dtlsnet "github.com/pion/dtls/v2/pkg/net"
)

type Listener struct {
	parent dtlsnet.PacketListener
	config Config
}

func Listen(laddr *net.UDPAddr, config Config) (*Listener, error) {

	listener, err := dtls.NewResumeListener("udp", laddr, &dtls.Config{
		ConnectionIDGenerator: dtls.RandomCIDGenerator(cidSize),
		KeyLogWriter:          log.Default().Writer(),
	})

	if err != nil {
		return nil, fmt.Errorf("error creating udp listener: %v", err)
	}

	return NewListener(listener, config)
}

func NewListener(inner dtlsnet.PacketListener, config Config) (*Listener, error) {
	return &Listener{parent: inner, config: config}, nil
}

func (l *Listener) Accept() (*Conn, error) {

	pconn, addr, err := l.parent.Accept()
	if err != nil {
		return nil, err
	}

	return ServerWithContext(context.Background(), pconn, addr, l.config)
}

// Close closes the listener.
func (l *Listener) Close() error {
	return l.parent.Close()
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.parent.Addr()
}
