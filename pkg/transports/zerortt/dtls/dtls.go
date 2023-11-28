package dtls

import (
	"encoding/hex"
	"fmt"
	"net"
	"sync"

	"github.com/pion/dtls/v2"
	dtlsnet "github.com/pion/dtls/v2/pkg/net"
	"github.com/pion/dtls/v2/pkg/protocol"
	"github.com/pion/dtls/v2/pkg/protocol/recordlayer"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/station/lib"
	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/ed25519/extra25519"
	"github.com/xtaci/kcp-go"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
)

const (
	cidSize    = 8
	listenPort = 41246
	receiveMTU = 8192
)

type Transport struct {
}

// Name returns name of the transport
func (Transport) Name() string {
	return "dtls-cid"
}

// LogPrefix returns log prefix of the transport
func (Transport) LogPrefix() string {
	return "DTLS-CID"
}

// GetIdentifier returns an identifier unique a registration
func (Transport) GetIdentifier(reg transports.Registration) string {
	return string(core.ConjureHMAC(reg.SharedSecret(), "dtlsCidTrasportHMACString"))
}

// NewTransport creates a new dtls transport
func Listen(proxyFunc func(covert string, clientConn net.Conn), privKey [lib.PrivateKeyLength]byte) error {
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
			var pconn net.PacketConn
			pconn, addr, err := listener.Accept()
			if err != nil {
				continue
			}

			state := &dtls.State{}

			packet := make([]byte, receiveMTU)
			n, readAddr, err := pconn.ReadFrom(packet)
			if err != nil {
				continue
			}

			pkts, err := recordlayer.ContentAwareUnpackDatagram(packet[:n], cidSize)
			if err != nil {
				continue
			}

			h := &recordlayer.Header{
				ConnectionID: make([]byte, cidSize),
			}

			pkt := pkts[0]
			if err := h.Unmarshal(pkt); err != nil {
				continue
			}

			if h.ContentType != protocol.ContentTypeConnectionID {
				continue
			}

			start := recordlayer.FixedHeaderSize + cidSize
			representative := &[32]byte{}
			if len(pkt) < (start + lib.PrivateKeyLength) {
				fmt.Printf("packet too small to contain a key\n")
				continue
			}
			n = copy(representative[:], pkt[start:start+lib.PrivateKeyLength])
			if n != len(representative) {
				continue
			}

			representative[31] &= 0x3F

			pubkey := &[32]byte{}
			extra25519.RepresentativeToPublicKey(pubkey, representative)

			newSharedSecret, err := curve25519.X25519(privKey[:], pubkey[:])
			if err != nil {
				continue
			}

			fmt.Printf("representative: %v\n", hex.EncodeToString(representative[:]))
			fmt.Printf("shared secret : %v\n", hex.EncodeToString(newSharedSecret))

			newData := pkt[start+lib.PrivateKeyLength:]

			h.ContentLen = uint16(len(newData))

			newHeader, err := h.Marshal()
			if err != nil {
				continue
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
				remote:     readAddr,
			}
			state, err = DTLSServerState(newSharedSecret)
			if err != nil {
				continue
			}

			conn, err := dtls.Resume(state, pconn, addr, config)
			if err != nil {
				continue
			}

			first := make([]byte, receiveMTU)
			n, err = conn.Read(first)
			if err != nil {
				continue
			}

			info := &pb.OneShotData{}
			if err := proto.Unmarshal(first[:n], info); err != nil {
				continue
			}

			econn := &edit1conn{
				Conn:      conn,
				onceBytes: info.GetEarlyData(),
			}

			kcpListener, err := kcp.ServeConn(nil, 0, 0, dtlsnet.PacketConnFromConn(econn))
			if err != nil {
				continue
			}

			kcpConn, err := kcpListener.Accept()
			if err != nil {
				continue
			}

			go proxyFunc(info.GetCovert(), kcpConn)

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
