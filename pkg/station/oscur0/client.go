package oscur0

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/pion/dtls/v2"
	pb "github.com/pion/dtls/v2/examples/util/proto"
	dtlsnet "github.com/pion/dtls/v2/pkg/net"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/xtaci/kcp-go"
	"google.golang.org/protobuf/proto"
)

const cj_pubkey = "0b63baad7f2f4bb5b547c53adc0fbb179852910607935e6f4b5639fd989b1156"

type dialFunc = func(ctx context.Context, network, laddr, raddr string) (net.Conn, error)

type Dialer struct {
	inner  dialFunc
	pubkey [32]byte
}

type Config struct {
	innerDialer dialFunc
	PrivKey     []byte
	PubKey      []byte
	Covert      string
}

// func Client(pconn net.PacketConn, raddr net.Addr, config Config) (net.Conn, error) {
// 	return ClientWithContext(context.Background(), pconn, raddr, config)
// }

func clientWithContext(ctx context.Context, pconn net.PacketConn, raddr net.Addr, config Config, keys *core.SharedKeys) (*Conn, error) {

	w1pconn := &write1pconn{
		PacketConn: pconn,
		onceBytes:  keys.Representative,
	}

	state, err := DTLSClientState(keys.SharedSecret)
	if err != nil {
		return nil, fmt.Errorf("error generateing dtls state: %v", err)
	}

	dtlsConn, err := dtls.Resume(state, w1pconn, raddr, &dtls.Config{
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		KeyLogWriter:         log.Default().Writer(),
	})
	if err != nil {
		return nil, err
	}

	fmt.Printf("representative: %v\n", hex.EncodeToString(keys.Representative))
	fmt.Printf("shared secret : %v\n", hex.EncodeToString(keys.SharedSecret))

	conn := &write1conn{
		Conn:   dtlsConn,
		covert: config.Covert,
	}

	kcpConn, err := kcp.NewConn("", nil, 0, 0, dtlsnet.PacketConnFromConn(conn))
	if err != nil {
		return nil, err
	}

	return &Conn{Conn: kcpConn}, nil
}

func resolveAddr(network, addrStr string) (net.Addr, error) {
	if addrStr == "" {
		return &net.IPAddr{}, nil
	}

	switch network {
	case "udp", "udp4", "udp6":
		return net.ResolveUDPAddr(network, addrStr)
	}

	return net.ResolveTCPAddr(network, addrStr)
}

type write1pconn struct {
	net.PacketConn
	onceBytes []byte
	doOnce    sync.Once
}

func (c *write1pconn) WriteTo(p []byte, addr net.Addr) (int, error) {
	var n int
	var err error
	c.doOnce.Do(func() {
		var new []byte
		new, err = c.editBuf(p)
		if err != nil {
			return
		}

		n, err = c.PacketConn.WriteTo(new, addr)
	})
	if err != nil {
		return 0, err
	}
	if n > 0 {
		return n, nil
	}

	return c.PacketConn.WriteTo(p, addr)
}

func (c *write1pconn) editBuf(p []byte) ([]byte, error) {
	pkts, err := recordlayer.ContentAwareUnpackDatagram(p, cidSize)
	if err != nil {
		return nil, err
	}

	h := &recordlayer.Header{
		ConnectionID: make([]byte, cidSize),
	}
	for i, pkt := range pkts {
		if err := h.Unmarshal(pkt); err != nil {
			continue
		}

		if h.ContentType != protocol.ContentTypeConnectionID {
			continue
		}

		start := recordlayer.FixedHeaderSize + cidSize
		appData := pkt[start:]

		h.ContentLen = uint16(len(c.onceBytes) + len(appData))

		newHeader, err := h.Marshal()
		if err != nil {
			return nil, err
		}

		combined := make([]byte, 0, len(newHeader)+len(c.onceBytes)+len(appData))
		combined = append(combined, newHeader...)
		combined = append(combined, c.onceBytes...)
		combined = append(combined, appData...)

		pkts[i] = combined
	}

	var flatData []byte
	for _, d := range pkts {
		flatData = append(flatData, d...)
	}

	return flatData, nil

}

type write1conn struct {
	net.Conn
	doOnce sync.Once
	covert string
}

func (c *write1conn) Write(p []byte) (int, error) {
	var n int
	var err error

	c.doOnce.Do(func() {
		id := make([]byte, 16)
		if _, err = rand.Read(id); err != nil {
			return
		}

		toSend := &pb.ConnInfo{
			Id:        id,
			EarlyData: p,
			Covert:    &c.covert,
		}

		var send []byte
		send, err = proto.Marshal(toSend)
		if err != nil {
			return
		}

		n, err = c.Conn.Write(send)
	})
	if err != nil {
		return 0, err
	}
	if n > 0 {
		return len(p), nil
	}

	return c.Conn.Write(p)
}
