package oscur0

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"
)

func dialQuic(addr *net.UDPAddr) (quic.EarlyConnection, error) {
	pconn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	tp := quic.Transport{
		Conn: pconn,
	}

	conn, err := tp.DialEarly(context.Background(), addr, &tls.Config{}, &quic.Config{})
	if err != nil {
		return nil, fmt.Errorf("error dialing quic connection: %v", err)
	}

	return conn, nil
}
