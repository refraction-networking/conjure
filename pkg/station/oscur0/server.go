package oscur0

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/pion/dtls/v2"
	dtlsnet "github.com/pion/dtls/v2/pkg/net"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
	"github.com/refraction-networking/conjure/pkg/station/lib"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/ed25519/extra25519"
	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
)

const privkeylen int = lib.PrivateKeyLength

// func Server(pconn net.PacketConn, raddr net.Addr, config Config) (net.Conn, error) {
// 	return ServerWithContext(context.Background(), pconn, raddr, config)
// }

func checkZeroPrivkey(arr []byte) error {
	for _, v := range arr {
		if v != 0 {
			return nil
		}
	}
	return fmt.Errorf("empty privkey")
}

type Conn struct {
	net.Conn
	info *pb.OneShotData
}

func (c *Conn) Covert() string {
	return c.info.GetCovert()
}

func ServerWithContext(ctx context.Context, pconn net.PacketConn, raddr net.Addr, config Config) (*Conn, error) {

	if err := checkZeroPrivkey(config.PrivKey); err != nil {
		return nil, err
	}

	state := &dtls.State{}

	packet := make([]byte, receiveMTU)
	n, _, err := pconn.ReadFrom(packet)
	if err != nil {
		return nil, fmt.Errorf("error reading from pconn: %v", err)
	}

	pkts, err := recordlayer.ContentAwareUnpackDatagram(packet[:n], cidSize)
	if err != nil {
		return nil, fmt.Errorf("error unpacking initial datagram: %v", err)
	}

	h := &recordlayer.Header{
		ConnectionID: make([]byte, cidSize),
	}

	pkt := pkts[0]
	if err := h.Unmarshal(pkt); err != nil {
		return nil, fmt.Errorf("error unmarshaling initial datagram: %v", err)
	}

	if h.ContentType != protocol.ContentTypeConnectionID {
		return nil, fmt.Errorf("initial datagram is not type cid: %v", err)
	}

	start := recordlayer.FixedHeaderSize + cidSize
	representative := &[32]byte{}
	if len(pkt) < (start + lib.PrivateKeyLength) {
		return nil, fmt.Errorf("initial packet too small to contain a key: lengh = %v, minimum = %v", len(pkt), (start + lib.PrivateKeyLength))
	}
	n = copy(representative[:], pkt[start:start+lib.PrivateKeyLength])
	if n != len(representative) {
		return nil, fmt.Errorf("copied %v, expected %v", n, len(representative))
	}

	// https://github.com/refraction-networking/conjure/blob/46fea9be3592c26b8841d53438264af5b740a544/pkg/core/keys.go#L59-L67
	representative[31] &= 0x3F

	pubkey := &[32]byte{}
	extra25519.RepresentativeToPublicKey(pubkey, representative)

	newSharedSecret, err := curve25519.X25519(config.PrivKey[:], pubkey[:])
	if err != nil {
		return nil, fmt.Errorf("error finding shared secret: %v", err)
	}

	fmt.Printf("representative: %v\n", hex.EncodeToString(representative[:]))
	fmt.Printf("shared secret : %v\n", hex.EncodeToString(newSharedSecret))

	newData := pkt[start+lib.PrivateKeyLength:]

	h.ContentLen = uint16(len(newData))

	newHeader, err := h.Marshal()
	if err != nil {
		return nil, fmt.Errorf("error marshaling header: %v", err)
	}

	combined := make([]byte, 0, len(newHeader)+len(newData))
	combined = append(combined, newHeader...)
	combined = append(combined, newData...)

	pkts[0] = combined

	var flatData []byte
	for _, d := range pkts {
		flatData = append(flatData, d...)
	}

	pconn = &edit1pconn{
		PacketConn: pconn,
		onceBytes:  flatData,
		remote:     raddr,
	}
	state, err = DTLSServerState(newSharedSecret)
	if err != nil {
		return nil, fmt.Errorf("error generating dtls state from shared secret: %v", err)
	}

	conn, err := dtls.Resume(state, pconn, raddr, &dtls.Config{
		ConnectionIDGenerator: dtls.RandomCIDGenerator(cidSize),
	})
	if err != nil {
		return nil, fmt.Errorf("error resuming dtls connection: %v", err)
	}

	first := make([]byte, receiveMTU)
	n, err = conn.Read(first)
	if err != nil {
		return nil, fmt.Errorf("error reading from dtls conn: %v", err)
	}

	info := &pb.OneShotData{}
	if err := proto.Unmarshal(first[:n], info); err != nil {
		return nil, fmt.Errorf("error unmarshaling one shot data: %v", err)
	}

	econn := &edit1conn{
		Conn:      conn,
		onceBytes: info.GetEarlyData(),
	}

	kcpListener, err := kcp.ServeConn(nil, 0, 0, dtlsnet.PacketConnFromConn(econn))
	if err != nil {
		return nil, fmt.Errorf("error serving kcp conn: %v", err)
	}

	kcpConn, err := kcpListener.Accept()
	if err != nil {
		return nil, fmt.Errorf("error accepting kcp conn: %v", err)
	}

	return &Conn{Conn: kcpConn, info: info}, nil
}
