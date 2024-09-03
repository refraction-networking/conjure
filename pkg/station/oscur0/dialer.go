package oscur0

import (
	"context"
	"fmt"
	"net"

	"github.com/refraction-networking/conjure/pkg/phantoms"
)

func Dial(raddr *net.UDPAddr, config Config) (*Conn, error) {

	pConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("error creating udp packet conn: %v", err)
	}

	return ClientWithContext(context.Background(), pConn, raddr, config)
}

func DialPhantom(config Config) (*Conn, error) {
	phantom, err := phantoms.SelectPhantom([]byte{}, phantoms.GetDefaultPhantomSubnets(), nil, true)
	if err != nil {
		return nil, fmt.Errorf("error selecting phantom: %v", err)
	}

	return Dial(&net.UDPAddr{IP: *phantom.IP()}, config)
}
