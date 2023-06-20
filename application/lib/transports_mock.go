package lib

import (
	"bytes"
	"net"

	"github.com/refraction-networking/conjure/pkg/core"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	mockID   = 0
	mockIDRO = 1
	mockIDFO = 2
)

type mockTransport struct {
	id uint
}

func (*mockTransport) Name() string      { return "MockTransport" }
func (*mockTransport) LogPrefix() string { return "MOCK" }

func (*mockTransport) GetIdentifier(d *DecoyRegistration) string {
	return string(core.ConjureHMAC(d.Keys.SharedSecret, "MockTransportHMACString"))
}

func (*mockTransport) WrapConnection(data *bytes.Buffer, c net.Conn, originalDst net.IP, regManager *RegistrationManager) (*DecoyRegistration, net.Conn, error) {
	return nil, nil, nil
}

func (*mockTransport) GetProto() pb.IPProto {
	return pb.IPProto_Tcp
}

// Match the parseParams for the min transport for now. We can add a better mock in the future if we
// need to evaluate more parameters.
func (*mockTransport) ParseParams(libVersion uint, data *anypb.Any) (any, error) {
	if data == nil {
		return nil, nil
	}

	// For backwards compatibility we create a generic transport params object
	// for transports that existed before the transportParams fields existed.
	if libVersion < randomizeDstPortMinVersion {
		f := false
		return &pb.GenericTransportParams{
			RandomizeDstPort: &f,
		}, nil
	}

	var m *pb.GenericTransportParams
	err := anypb.UnmarshalTo(data, m, proto.UnmarshalOptions{})
	return m, err
}

// GetDstPort Given the library version, a seed, and a generic object
// containing parameters the transport should be able to return the
// destination port that a clients phantom connection will attempt to reach
func (m *mockTransport) GetDstPort(libVersion uint, seed []byte, parameters any) (uint16, error) {
	if m.id == mockIDFO || !parameters.(*pb.GenericTransportParams).GetRandomizeDstPort() {
		// mock return non randomized
		return 443, nil
	}

	return 444, nil
}
