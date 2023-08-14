package dtls

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/pion/stun"
)

const ttl = 5
const defaultTTL = 64

type fileConn interface {
	File() (*os.File, error)
}

func openUDP(ctx context.Context, laddr, addr string, dialer dialFunc) error {
	// Create a UDP connection
	conn, err := dialer(ctx, "udp", laddr, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Write data to the connection
	_, err = conn.Write([]byte(""))
	if err != nil {
		return err
	}

	// No error
	return nil
}

var (
	privPortSingle int
	pubPortSingle  int
)

func publicAddr(stunServer string, dialer func(ctx context.Context, network, laddr, raddr string) (net.Conn, error)) (privatePort int, publicPort int, err error) {

	if privPortSingle != 0 && pubPortSingle != 0 {
		return privPortSingle, pubPortSingle, nil
	}

	udpConn, err := dialer(context.Background(), "udp", "", stunServer)
	if err != nil {
		return 0, 0, fmt.Errorf("error connecting to STUN server: %v", err)
	}
	defer udpConn.Close()

	localAddr, err := net.ResolveUDPAddr(udpConn.LocalAddr().Network(), udpConn.LocalAddr().String())
	if err != nil {
		return 0, 0, fmt.Errorf("error resolving local address: %v", err)
	}

	client, err := stun.NewClient(udpConn)
	if err != nil {
		return 0, 0, fmt.Errorf("error creating STUN client: %v", err)
	}

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	var xorAddr stun.XORMappedAddress

	err = client.Do(message, func(res stun.Event) {
		if res.Error != nil {
			err = res.Error
			return
		}

		err = xorAddr.GetFrom(res.Message)
		if err != nil {
			return
		}
	})

	if err != nil {
		return 0, 0, fmt.Errorf("error getting address from STUN: %v", err)
	}

	privPortSingle = localAddr.Port
	pubPortSingle = xorAddr.Port

	return localAddr.Port, xorAddr.Port, nil
}
