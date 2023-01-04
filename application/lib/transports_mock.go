package lib

import (
	"bytes"
	"net"

	pb "github.com/refraction-networking/gotapdance/protobuf"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	mockID   = 0
	mockIDRO = 1
	mockIDFO = 2
)

type mockTransport struct{}

func (mockTransport) Name() string      { return "MockTransport" }
func (mockTransport) LogPrefix() string { return "MOCK" }

func (mockTransport) GetIdentifier(d *DecoyRegistration) string {
	return string(d.Keys.ConjureHMAC("MockTransportHMACString"))
}

func (mockTransport) WrapConnection(data *bytes.Buffer, c net.Conn, originalDst net.IP, regManager *RegistrationManager) (*DecoyRegistration, net.Conn, error) {
	return nil, nil, nil
}

func (mockTransport) GetProto() pb.IpProto {
	return pb.IpProto_Tcp
}

func (mockTransport) ParseParams(data *anypb.Any) (any, error) {
	var m *pb.GenericTransportParams
	err := anypb.UnmarshalTo(data, m, proto.UnmarshalOptions{})
	return m, err
}

// Mock can be used as a randomizing dst port transport
func (mockTransport) GetPortSelector() func([]byte, any) (uint16, error) {
	return func([]byte, any) (uint16, error) { return 444, nil }
}

// Mock can be used as a fixed dst port transport
func (mockTransport) ServicePort() uint16 {
	return 443
}

// mtro MockTransportRandomizinOnly
type mtro struct{}

func (mtro) Name() string      { return "MockTransportRandomizing" }
func (mtro) LogPrefix() string { return "MOCKRO" }

func (mtro) GetIdentifier(d *DecoyRegistration) string {
	return string(d.Keys.ConjureHMAC("MockTransportHMACString"))
}

func (mtro) WrapConnection(data *bytes.Buffer, c net.Conn, originalDst net.IP, regManager *RegistrationManager) (*DecoyRegistration, net.Conn, error) {
	return nil, nil, nil
}

func (mtro) GetProto() pb.IpProto {
	return pb.IpProto_Tcp
}

func (mtro) ParseParams(data *anypb.Any) (any, error) {
	var m *pb.GenericTransportParams
	err := anypb.UnmarshalTo(data, m, proto.UnmarshalOptions{})
	return m, err
}

// Mock can be used as a randomizing dst port transport
func (mtro) GetPortSelector() func([]byte, any) (uint16, error) {
	return func([]byte, any) (uint16, error) { return 444, nil }
}

// mtfo MockTransportFixedOnly
type mtfo struct{}

func (mtfo) Name() string      { return "MockTransportFixed" }
func (mtfo) LogPrefix() string { return "MOCKFO" }

func (mtfo) GetIdentifier(d *DecoyRegistration) string {
	return string(d.Keys.ConjureHMAC("MockTransportHMACString"))
}

func (mtfo) WrapConnection(data *bytes.Buffer, c net.Conn, originalDst net.IP, regManager *RegistrationManager) (*DecoyRegistration, net.Conn, error) {
	return nil, nil, nil
}

func (mtfo) GetProto() pb.IpProto {
	return pb.IpProto_Tcp
}

func (mtfo) ParseParams(data *anypb.Any) (any, error) {
	var m *pb.GenericTransportParams
	err := anypb.UnmarshalTo(data, m, proto.UnmarshalOptions{})
	return m, err
}

// Mock can be used as a fixed dst port transport
func (mtfo) ServicePort() uint16 {
	return 443
}
