package regprocessor

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	zmq "github.com/pebbe/zmq4"
	"github.com/refraction-networking/conjure/pkg/metrics"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	log "github.com/sirupsen/logrus"
)

var (
	secretHex = []byte(`1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef`)
	secret    []byte
)

func newRegProcessor() RegProcessor {
	return RegProcessor{
		metrics: metrics.NewMetrics(log.NewEntry(log.StandardLogger()), 5*time.Second),
	}
}

func init() {
	secret = make([]byte, SecretLength)
	_, err := hex.Decode(secret, secretHex)
	if err != nil {
		panic(err)
	}
}

func generateC2SWrapperPayload() (c2sPayload *pb.C2SWrapper, c2sPayloadBytes []byte) {
	generation := uint32(0)
	covert := "1.2.3.4:1234"

	// We need pointers to bools. This is nasty D:
	trueBool := true
	falseBool := false
	v := uint32(1)

	c2s := pb.ClientToStation{
		DecoyListGeneration: &generation,
		CovertAddress:       &covert,
		V4Support:           &trueBool,
		V6Support:           &trueBool,
		ClientLibVersion:    &v,
		Flags: &pb.RegistrationFlags{
			ProxyHeader: &trueBool,
			Use_TIL:     &trueBool,
			UploadOnly:  &falseBool,
		},
	}

	c2sPayload = &pb.C2SWrapper{
		SharedSecret:        secret,
		RegistrationPayload: &c2s,
	}

	c2sPayloadBytes, _ = proto.Marshal(c2sPayload)

	return
}

func TestC2SWrapperProcessing(t *testing.T) {
	c2sPayload, _ := generateC2SWrapperPayload()

	p := newRegProcessor()

	zmqPayload, err := p.processC2SWrapper(c2sPayload, []byte(net.ParseIP("127.0.0.1").To16()), pb.RegistrationSource_API)
	if err != nil {
		t.Fatalf("failed to generate ZMQ payload: expected nil, got %v", err)
	}

	var retrievedPayload pb.C2SWrapper
	err = proto.Unmarshal(zmqPayload, &retrievedPayload)
	if err != nil {
		t.Fatalf("failed to unmarshal ClientToStation from ZMQ payload: expected nil, got %v", err)
	}

	if retrievedPayload.RegistrationPayload.GetDecoyListGeneration() != c2sPayload.RegistrationPayload.GetDecoyListGeneration() {
		t.Fatalf("decoy list generation in retrieved ClientToStation doesn't match: expected %d, got %d", c2sPayload.RegistrationPayload.GetDecoyListGeneration(), retrievedPayload.RegistrationPayload.GetDecoyListGeneration())
	}

	if retrievedPayload.RegistrationPayload.GetCovertAddress() != c2sPayload.RegistrationPayload.GetCovertAddress() {
		t.Fatalf("covert address in retrieved ClientToStation doesn't match: expected %s, got %s", c2sPayload.RegistrationPayload.GetCovertAddress(), retrievedPayload.RegistrationPayload.GetCovertAddress())
	}

	if retrievedPayload.RegistrationPayload.GetV4Support() != c2sPayload.RegistrationPayload.GetV4Support() {
		t.Fatalf("v4 support in retrieved ClientToStation doesn't match: expected %v, got %v", c2sPayload.RegistrationPayload.GetV4Support(), retrievedPayload.RegistrationPayload.GetV4Support())
	}

	if retrievedPayload.RegistrationPayload.GetV6Support() != c2sPayload.RegistrationPayload.GetV6Support() {
		t.Fatalf("v6 support in retrieved ClientToStation doesn't match: expected %v, got %v", c2sPayload.RegistrationPayload.GetV6Support(), retrievedPayload.RegistrationPayload.GetV6Support())
	}

	if net.IP(retrievedPayload.GetRegistrationAddress()).String() != "127.0.0.1" {
		t.Fatalf("source address in retrieved C2Swrapper doesn't match: expected %v, got %v", "127.0.0.1", net.IP(retrievedPayload.GetRegistrationAddress()).String())
	}

	if retrievedPayload.GetRegistrationSource() != pb.RegistrationSource_API {
		t.Fatalf("Registration source in retrieved C2Swrapper doesn't match: expected %v, got %v", pb.RegistrationSource_API, retrievedPayload.GetRegistrationSource())
	}

	altSource := pb.RegistrationSource_DetectorPrescan
	c2sPayload.RegistrationSource = &altSource
	zmqPayload, err = p.processC2SWrapper(c2sPayload, []byte(net.ParseIP("127.0.0.1").To16()), pb.RegistrationSource_API)
	if err != nil {
		t.Fatalf("failed to generate ZMQ payload: expected nil, got %v", err)
	}

	var retrievedPayload1 pb.C2SWrapper
	err = proto.Unmarshal(zmqPayload, &retrievedPayload1)
	if err != nil {
		t.Fatalf("failed to unmarshal ClientToStation from ZMQ payload: expected nil, got %v", err)
	}

	if retrievedPayload1.GetRegistrationSource() != pb.RegistrationSource_DetectorPrescan {
		t.Fatalf("Registration source in retrieved C2Swrapper doesn't match: expected %v, got %v", pb.RegistrationSource_DetectorPrescan, retrievedPayload.GetRegistrationSource())
	}
}

func BenchmarkRegistration(b *testing.B) {
	sock, err := zmq.NewSocket(zmq.PUB)
	if err != nil {
		log.Fatalln("failed to set up ZMQ socket:", err)
	}

	err = sock.Bind("tcp://*:5589")
	if err != nil {
		log.Fatalln("failed to bind ZMQ socket:", err)
	}

	s := newRegProcessor()
	s.sock = sock

	body, _ := generateC2SWrapperPayload()
	b.ResetTimer()

	sourceIP := net.ParseIP("1.2.3.4:443")

	for i := 0; i < b.N; i++ {
		err := s.RegisterUnidirectional(body, pb.RegistrationSource_API, []byte(sourceIP))
		if err != nil {
			b.Errorf("error in sending registration request: %v", err)
		}
	}
}

type fakeZmqSender struct {
	fakeSend func([]byte, zmq.Flag) (int, error)
}

func (z fakeZmqSender) SendBytes(data []byte, flag zmq.Flag) (int, error) {
	return z.fakeSend(data, flag)
}

func TestRegisterUnidirectional(t *testing.T) {
	originalIP := "1.2.3.4"
	updatedIP := "4.3.2.1"

	c2sPayload, _ := generateC2SWrapperPayload()
	regSrc := pb.RegistrationSource_API
	c2sPayload.RegistrationSource = &regSrc
	c2sPayload.RegistrationAddress = net.ParseIP(originalIP).To16()

	fakeSendFunc := func(m []byte, flag zmq.Flag) (int, error) {
		// We already tested the payload generation above, so here we're just
		// confirming it arrives with the correct modifications
		payload := &pb.C2SWrapper{}
		if err := proto.Unmarshal(m, payload); err != nil {
			t.Fatalf("Bad C2Swrapper returned")
		}

		// Check if registration source is correct
		if payload.GetRegistrationSource() != regSrc {
			t.Fatalf("Incorrect registration source returned")
		}

		// If the Address isn't re-written for specified registrar source throw error
		if net.IP(payload.GetRegistrationAddress()).String() != updatedIP {
			t.Fatalf("Registration Address should be overwritten for specified registrar")
		}

		return len(m), nil
	}

	fakeSender := fakeZmqSender{
		fakeSend: fakeSendFunc,
	}

	s := newRegProcessor()
	s.sock = fakeSender

	err := s.RegisterUnidirectional(c2sPayload, regSrc, net.ParseIP(updatedIP))

	if err != nil {
		t.Errorf("error in sending registration request: %v", err)
	}

}

func TestUnspecifiedReg(t *testing.T) {
	originalIP := "1.2.3.4"
	updatedIP := "4.3.2.1"

	c2sPayload, _ := generateC2SWrapperPayload()
	regSrc := pb.RegistrationSource_Unspecified
	realRegSrc := pb.RegistrationSource_API
	c2sPayload.RegistrationSource = &regSrc
	c2sPayload.RegistrationAddress = net.ParseIP(originalIP).To16()

	fakeSendFunc := func(m []byte, flag zmq.Flag) (int, error) {
		// We already tested the payload generation above, so here we're just
		// confirming it arrives with the correct modifications
		payload := &pb.C2SWrapper{}
		if err := proto.Unmarshal(m, payload); err != nil {
			t.Fatalf("Bad C2Swrapper returned")
		}

		// Check if registration source is correct
		if payload.GetRegistrationSource() != realRegSrc {
			t.Fatalf("Incorrect registration source returned")
		}

		// If the Address isn't re-written for specified registrar source throw error
		if net.IP(payload.GetRegistrationAddress()).String() == updatedIP {
			t.Fatalf("Registration Address should not be overwritten for specified registrar")
		}

		return len(m), nil
	}

	fakeSender := fakeZmqSender{
		fakeSend: fakeSendFunc,
	}

	s := newRegProcessor()
	s.sock = fakeSender

	err := s.RegisterUnidirectional(c2sPayload, realRegSrc, net.ParseIP(updatedIP))

	if err != nil {
		t.Errorf("error in sending registration request: %v", err)
	}

}

func TestUpdateIP(t *testing.T) {
	originalIP := "1.2.3.4"
	updatedIP := "4.3.2.1"

	c2sRegSrc := pb.RegistrationSource_DetectorPrescan
	usedRegSrc := pb.RegistrationSource_API

	c2sPayload, _ := generateC2SWrapperPayload()
	c2sPayload.RegistrationSource = &c2sRegSrc
	c2sPayload.RegistrationAddress = net.ParseIP(originalIP).To16()

	fakeSendFunc := func(m []byte, flag zmq.Flag) (int, error) {
		// We already tested the payload generation above, so here we're just
		// confirming it arrives with the correct modifications
		payload := &pb.C2SWrapper{}
		if err := proto.Unmarshal(m, payload); err != nil {
			t.Fatalf("Bad C2Swrapper returned")
		}

		// If the Address isn't re-written for specified registrar source throw error
		if net.IP(payload.GetRegistrationAddress()).String() != originalIP {
			t.Fatalf("Registration Address should NOT be overwritten for specified registrar")
		}

		return len(m), nil
	}

	fakeSender := fakeZmqSender{
		fakeSend: fakeSendFunc,
	}

	s := newRegProcessor()
	s.sock = fakeSender

	err := s.RegisterUnidirectional(c2sPayload, usedRegSrc, net.ParseIP(updatedIP))

	if err != nil {
		t.Errorf("error in sending registration request: %v", err)
	}
}

type fakeIpSelector struct {
	v4Addr net.IP
	v6Addr net.IP
}

func (f fakeIpSelector) Select(seed []byte, generation uint, clientLibVer uint, v6Support bool) (net.IP, error) {
	if v6Support {
		return f.v6Addr, nil
	}
	return f.v4Addr, nil
}

func TestRegisterBidirectional(t *testing.T) {
	originalIP := "1.2.3.4"
	updatedIP := "4.3.2.1"

	regSrc := pb.RegistrationSource_BidirectionalAPI

	fakeSendFunc := func(m []byte, flag zmq.Flag) (int, error) {
		// We already tested the payload generation above, so here we're just
		// confirming it arrives with the correct modifications
		payload := &pb.C2SWrapper{}
		if err := proto.Unmarshal(m, payload); err != nil {
			t.Fatalf("Bad C2Swrapper returned")
		}

		// Check if registration source is correct
		if payload.GetRegistrationSource() != regSrc {
			t.Fatalf("Incorrect registration source returned")
		}

		// If the Address isn't re-written for specified registrar source throw error
		if net.IP(payload.GetRegistrationAddress()).String() != updatedIP {
			t.Fatalf("Registration Address should be overwritten for specified registrar")
		}

		return len(m), nil
	}

	fakeSender := fakeZmqSender{
		fakeSend: fakeSendFunc,
	}

	fakeV4Phantom := "9.8.7.6"
	fakeV6Phantom := "fbdc:8e7d:872c:ce49:5470:8223:db34:7d67"

	fakeSelector := fakeIpSelector{
		v4Addr: net.ParseIP(fakeV4Phantom),
		v6Addr: net.ParseIP(fakeV6Phantom),
	}

	s := newRegProcessor()
	s.sock = fakeSender
	s.ipSelector = fakeSelector

	// Client sends to station v4 or v6, shared secret, etc.
	c2sPayload, _ := generateC2SWrapperPayload() // v4 support
	c2sPayload.RegistrationSource = &regSrc
	c2sPayload.RegistrationAddress = net.ParseIP(originalIP).To16()

	resp, err := s.RegisterBidirectional(c2sPayload, regSrc, net.ParseIP(updatedIP))

	if err != nil {
		t.Fatal(err)
	}

	respIpv4 := make(net.IP, 4)
	binary.BigEndian.PutUint32(respIpv4, resp.GetIpv4Addr())

	if net.IP(respIpv4).String() != fakeV4Phantom {
		t.Fatal("response ip incorrect")
	}

	respIpv6 := resp.GetIpv6Addr()

	if net.IP(respIpv6).String() != fakeV6Phantom {
		t.Fatal("response ip incorrect")
	}
}
