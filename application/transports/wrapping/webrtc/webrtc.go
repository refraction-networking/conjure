package webrtc

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/Gaukas/seed2sdp"
	rtc "github.com/GaukasWang/conjuRTC/lib"
	"github.com/pion/ice/v2"
	dd "github.com/refraction-networking/conjure/application/lib"
	tdtransport "github.com/refraction-networking/conjure/application/transports"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

// Implements dd.UDPTransport interface
type Transport struct {
	clientSetup rtc.ClientSetup
	mapPortMux  map[uint16]ice.UDPMux
	minPort     int
	maxPort     int
}

func DefaultTransport() *Transport {
	return &Transport{
		clientSetup: rtc.CLIENT_SETUP_ACTPASS,
		mapPortMux:  make(map[uint16]ice.UDPMux),
		minPort:     8900,
		maxPort:     8999,
	}
}

func (t *Transport) Name() string      { return "WebRTCDataChannel" }
func (t *Transport) LogPrefix() string { return "WEBRTC" }

func (t *Transport) GetIdentifier(d *dd.DecoyRegistration) string {
	if d.Transport == pb.TransportType_Webrtc {
		if d.WebRTCSignal != nil && d.WebRTCSignal.Seed != nil {
			return *d.WebRTCSignal.Seed
		}
	}
	return "NOT_WEBRTC_TRANSPORT"
}

func (t *Transport) PortRange(min, max int) error {
	if max <= min {
		return errors.New("max port must be greater than min port")
	}
	rtc.SetBasePort(uint16(min))
	rtc.SetPortRange(int64(max - min))
	t.minPort = min
	t.maxPort = max
	return nil
}

func (t *Transport) Listen(port int, rawsocket *net.UDPConn) error {
	if t.mapPortMux == nil {
		t.mapPortMux = make(map[uint16]ice.UDPMux)
	}
	if port < 0 || port > 65535 {
		return errors.New("port must be between 0 and 65535")
	}
	t.mapPortMux[uint16(port)] = rtc.Conn2Mux(rawsocket)

	return nil
}

func (t *Transport) HandleRegistration(ctx context.Context, reg *dd.DecoyRegistration) (net.Conn, error) {
	if reg.Transport != pb.TransportType_Webrtc {
		return nil, tdtransport.ErrNotTransport
	}
	if reg.WebRTCSignal == nil || reg.WebRTCSignal.Seed == nil || reg.WebRTCSignal.GetSdp() == nil {
		return nil, tdtransport.ErrTryAgain
	}

	// Debug: Print seed and SDP Type
	fmt.Printf("%s: Handling registration with seed[%s] and sdp type[%d]\n", t.LogPrefix(), reg.WebRTCSignal.GetSeed(), reg.WebRTCSignal.Sdp.GetType())

	// Recover Seed and SDP
	seed := reg.WebRTCSignal.GetSeed()
	deflatedSDP := seed2sdp.SDPDeflated{
		SDPType:    uint8(reg.WebRTCSignal.Sdp.GetType()),
		Candidates: []seed2sdp.DeflatedICECandidate{},
	}
	// SDP Type assertion: currently SDP must be of type "offer"
	if deflatedSDP.SDPType != seed2sdp.SDPOffer {
		return nil, fmt.Errorf("%s: SDP type must be offer", t.LogPrefix())
	}

	for _, c := range reg.WebRTCSignal.Sdp.GetCandidates() {
		candidate := seed2sdp.DeflatedICECandidate{
			IPUpper64:  c.GetIpUpper(),
			IPLower64:  c.GetIpLower(),
			Composed32: c.GetComposedInfo(),
		}
		deflatedSDP.Candidates = append(deflatedSDP.Candidates, candidate)
	}
	sdpParsed, err := deflatedSDP.Inflate()
	if err != nil {
		return nil, tdtransport.ErrTryAgain
	}
	// Fetch Mux
	mux, ok := t.mapPortMux[rtc.RandPort(seed)]
	if !ok {
		return nil, tdtransport.ErrNotTransport
	}

	conn, _, err := rtc.Mux2WebRTC(ctx, mux, []string{seed}, []*seed2sdp.SDP{sdpParsed}, t.clientSetup)
	return conn, err
}
