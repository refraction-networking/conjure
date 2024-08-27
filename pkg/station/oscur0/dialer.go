package oscur0

import (
	"context"
	"fmt"
	"net"
)

func Dial(raddr *net.UDPAddr, config Config) (*Conn, error) {

	pConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("error creating udp packet conn: %v", err)
	}

	return ClientWithContext(context.Background(), pConn, raddr, config)
}
