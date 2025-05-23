package regprocessor

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	zmq "github.com/pebbe/zmq4"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/metrics"
	"github.com/refraction-networking/conjure/pkg/phantoms"
	"github.com/refraction-networking/conjure/pkg/regserver/overrides"
	"github.com/refraction-networking/conjure/pkg/transports"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/min"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/prefix"
	pb "github.com/refraction-networking/conjure/proto"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var (
	secretHex = []byte(`1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef`)
	secret    []byte
)

func mockRegProcessor() RegProcessor {
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
	t := pb.TransportType_Min

	c2s := pb.ClientToStation{
		Transport:           &t,
		DecoyListGeneration: &generation,
		CovertAddress:       &covert,
		V4Support:           &trueBool,
		V6Support:           &trueBool,
		ClientLibVersion:    proto.Uint32(core.CurrentClientLibraryVersion()),
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

	p := mockRegProcessor()

	zmqPayload, err := p.processC2SWrapper(c2sPayload, []byte(net.ParseIP("127.0.0.1").To16()), pb.RegistrationSource_API)
	require.Nil(t, err, "failed to generate ZMQ payload: expected nil, got %v", err)

	var retrievedPayload pb.C2SWrapper
	err = proto.Unmarshal(zmqPayload, &retrievedPayload)
	require.Nil(t, err, "failed to unmarshal ClientToStation from ZMQ payload: expected nil, got %v", err)
	require.Equal(t, c2sPayload.RegistrationPayload.GetDecoyListGeneration(), retrievedPayload.RegistrationPayload.GetDecoyListGeneration())
	require.Equal(t, c2sPayload.RegistrationPayload.GetCovertAddress(), retrievedPayload.RegistrationPayload.GetCovertAddress())
	require.Equal(t, c2sPayload.RegistrationPayload.GetV4Support(), retrievedPayload.RegistrationPayload.GetV4Support())
	require.Equal(t, c2sPayload.RegistrationPayload.GetV6Support(), retrievedPayload.RegistrationPayload.GetV6Support())
	require.Equal(t, "127.0.0.1", net.IP(retrievedPayload.GetRegistrationAddress()).String())
	require.Equal(t, pb.RegistrationSource_API, retrievedPayload.GetRegistrationSource())

	altSource := pb.RegistrationSource_DetectorPrescan
	c2sPayload.RegistrationSource = &altSource
	zmqPayload, err = p.processC2SWrapper(c2sPayload, []byte(net.ParseIP("127.0.0.1").To16()), pb.RegistrationSource_API)
	require.Nil(t, err, "failed to generate ZMQ payload: expected nil, got %v", err)

	var retrievedPayload1 pb.C2SWrapper
	err = proto.Unmarshal(zmqPayload, &retrievedPayload1)
	require.Nil(t, err, "failed to unmarshal ClientToStation from ZMQ payload: expected nil, got %v", err)
	require.Equal(t, pb.RegistrationSource_DetectorPrescan, retrievedPayload1.GetRegistrationSource())

	_, err = p.processC2SWrapper(c2sPayload, []byte(net.ParseIP("127.0.0.1").To16()), pb.RegistrationSource_API)
	require.Nil(t, err, "failed to generate ZMQ payload: expected nil, got %v", err)

	pub, priv, err := ed25519.GenerateKey(nil)
	require.Nil(t, err)
	port := uint32(22)
	rr := &pb.RegistrationResponse{DstPort: &port}
	c2sPayload.RegistrationResponse = rr
	p.privkey = priv
	p.authenticated = true
	zmqPayload, err = p.processC2SWrapper(c2sPayload, []byte(net.ParseIP("127.0.0.1").To16()), pb.RegistrationSource_API)
	require.Nil(t, err, "failed to generate ZMQ payload: expected nil, got %v", err)

	var retrievedPayload2 pb.C2SWrapper
	err = proto.Unmarshal(zmqPayload, &retrievedPayload2)
	require.Nil(t, err, "failed to unmarshal ClientToStation from ZMQ payload: expected nil, got %v", err)

	rrb, err := proto.Marshal(rr)
	require.Nil(t, err)
	require.Equal(t, rrb, retrievedPayload2.RegRespBytes)
	require.True(t, ed25519.Verify(pub, retrievedPayload2.RegRespBytes, retrievedPayload2.RegRespSignature))
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

	s := mockRegProcessor()
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

func (z fakeZmqSender) Close() error {
	return nil
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

		// If the Address is re-written for specified registrar source throw error
		if net.IP(payload.GetRegistrationAddress()).String() != originalIP {
			t.Fatalf("Registration Address should not be overwritten for specified registrar")
		}

		return len(m), nil
	}

	fakeSender := fakeZmqSender{
		fakeSend: fakeSendFunc,
	}

	s := mockRegProcessor()
	s.sock = fakeSender

	err := s.RegisterUnidirectional(c2sPayload, regSrc, net.ParseIP(updatedIP))

	if err != nil {
		t.Errorf("error in sending registration request: %v", err)
	}

}

func TestRegisterUnidirectionalNoIp(t *testing.T) {
	updatedIP := "4.3.2.1"

	c2sPayload, _ := generateC2SWrapperPayload()
	regSrc := pb.RegistrationSource_API
	c2sPayload.RegistrationSource = &regSrc

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

	s := mockRegProcessor()
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

	s := mockRegProcessor()
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

	s := mockRegProcessor()
	s.sock = fakeSender

	err := s.RegisterUnidirectional(c2sPayload, usedRegSrc, net.ParseIP(updatedIP))

	if err != nil {
		t.Errorf("error in sending registration request: %v", err)
	}
}

type fakeIPSelector struct {
	v4Addr net.IP
	v6Addr net.IP
}

func (f fakeIPSelector) Select(seed []byte, generation uint, clientLibVer uint, v6Support bool) (*phantoms.PhantomIP, error) {
	if v6Support {
		return phantoms.IP(f.v6Addr, true), nil
	}
	return phantoms.IP(f.v4Addr, true), nil
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

		// If the Address is re-written for specified registrar source throw error
		if net.IP(payload.GetRegistrationAddress()).String() != originalIP {
			t.Fatalf("Registration Address should not be overwritten for specified registrar")
		}

		return len(m), nil
	}

	fakeSender := fakeZmqSender{
		fakeSend: fakeSendFunc,
	}

	fakeV4Phantom := "9.8.7.6"
	fakeV6Phantom := "fbdc:8e7d:872c:ce49:5470:8223:db34:7d67"

	fakeSelector := fakeIPSelector{
		v4Addr: net.ParseIP(fakeV4Phantom),
		v6Addr: net.ParseIP(fakeV6Phantom),
	}

	s := mockRegProcessor()
	s.sock = fakeSender
	s.ipSelector = fakeSelector
	err := s.AddTransport(pb.TransportType_Min, min.Transport{})
	require.Nil(t, err)

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

func TestRegisterBidirectionalNoIp(t *testing.T) {
	updatedIP := "4.3.2.1"

	c2sPayload, _ := generateC2SWrapperPayload()
	regSrc := pb.RegistrationSource_BidirectionalAPI
	c2sPayload.RegistrationSource = &regSrc

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

	s := mockRegProcessor()
	s.sock = fakeSender

	fakeV4Phantom := "9.8.7.6"
	fakeV6Phantom := "fbdc:8e7d:872c:ce49:5470:8223:db34:7d67"

	fakeSelector := fakeIPSelector{
		v4Addr: net.ParseIP(fakeV4Phantom),
		v6Addr: net.ParseIP(fakeV6Phantom),
	}

	s.ipSelector = fakeSelector
	err := s.AddTransport(pb.TransportType_Min, min.Transport{})
	require.Nil(t, err)

	_, err = s.RegisterBidirectional(c2sPayload, regSrc, net.ParseIP(updatedIP))

	if err != nil {
		t.Errorf("error in sending registration request: %v", err)
	}

}

func TestRegProcessBdReq(t *testing.T) {

	r := &RegProcessor{
		zmqMutex:      sync.Mutex{},
		selectorMutex: sync.RWMutex{},
		authenticated: false,
		ipSelector:    &mockIPSelector{},
		regOverrides:  nil,
	}

	err := r.AddTransport(pb.TransportType_Prefix, prefix.DefaultSet())
	require.Nil(t, err)

	tspt := pb.TransportType_Prefix
	trueptr := true
	id := int32(prefix.Min)
	params, err := anypb.New(&pb.PrefixTransportParams{
		PrefixId:         &id,
		RandomizeDstPort: &trueptr,
	})
	require.Nil(t, err)

	clv := uint32(4)
	c2sw := &pb.C2SWrapper{
		RegistrationPayload: &pb.ClientToStation{
			ClientLibVersion: &clv,
			Transport:        &tspt,
			V6Support:        &trueptr,
			V4Support:        &trueptr,
			TransportParams:  params,
		},
		SharedSecret: make([]byte, 32),
	}

	resp, err := r.processBdReq(c2sw)
	require.Nil(t, err)
	require.NotNil(t, resp)
}

type mockIPSelector struct{}

func (*mockIPSelector) Select([]byte, uint, uint, bool) (*phantoms.PhantomIP, error) {
	ip := net.ParseIP("8.8.8.8")
	return phantoms.IP(ip, true), nil
}

func TestRegProcessBdReqOverride(t *testing.T) {
	clv := uint32(4)
	tspt := pb.TransportType_Prefix
	trueptr := true
	falseptr := false
	id := int32(prefix.Min)

	r := &RegProcessor{
		zmqMutex:      sync.Mutex{},
		selectorMutex: sync.RWMutex{},
		authenticated: false,
		ipSelector:    &mockIPSelector{},
		regOverrides:  interfaces.Overrides([]interfaces.RegOverride{overrides.NewRandPrefixOverride()}),
	}

	err := r.AddTransport(pb.TransportType_Prefix, prefix.DefaultSet())
	require.Nil(t, err)

	params, err := anypb.New(&pb.PrefixTransportParams{
		PrefixId:         &id,
		RandomizeDstPort: &trueptr,
	})
	require.Nil(t, err)

	c2sw := &pb.C2SWrapper{
		RegistrationPayload: &pb.ClientToStation{
			ClientLibVersion:          &clv,
			Transport:                 &tspt,
			V6Support:                 &trueptr,
			V4Support:                 &trueptr,
			TransportParams:           params,
			DisableRegistrarOverrides: &falseptr,
		},
		SharedSecret: make([]byte, 32),
	}

	resp, err := r.processBdReq(c2sw)
	require.Nil(t, err)
	require.NotNil(t, resp)
	require.Equal(t, resp, c2sw.GetRegistrationResponse())

	// ----

	// ensure that the expected prefix (the one provided) is returned if DisableRegistrarOverrides
	// is set.

	params, err = anypb.New(&pb.PrefixTransportParams{
		PrefixId:         &id,
		RandomizeDstPort: &falseptr,
	})
	require.Nil(t, err)

	c2sw = &pb.C2SWrapper{
		RegistrationPayload: &pb.ClientToStation{
			ClientLibVersion:          &clv,
			Transport:                 &tspt,
			V6Support:                 &trueptr,
			V4Support:                 &trueptr,
			TransportParams:           params,
			DisableRegistrarOverrides: &trueptr,
		},
		SharedSecret: make([]byte, 32),
	}

	resp, err = r.processBdReq(c2sw)
	require.Nil(t, err)
	require.Nil(t, resp.GetTransportParams())

	// ----
	// // ensure that a returned override prefix does not have to be in the Default Prefix set.

	params, err = anypb.New(&pb.PrefixTransportParams{
		PrefixId:         &id,
		RandomizeDstPort: &falseptr,
	})
	require.Nil(t, err)

	c2sw = &pb.C2SWrapper{
		RegistrationPayload: &pb.ClientToStation{
			ClientLibVersion:          &clv,
			Transport:                 &tspt,
			V6Support:                 &trueptr,
			V4Support:                 &trueptr,
			TransportParams:           params,
			DisableRegistrarOverrides: &falseptr,
		},
		SharedSecret: make([]byte, 32),
	}

	fixedPrefix := &mockPrefix{[]byte("aaaa"), -2}
	r.regOverrides = interfaces.Overrides([]interfaces.RegOverride{overrides.NewFixedPrefixOverride(fixedPrefix)})

	resp, err = r.processBdReq(c2sw)
	require.Nil(t, err)
	require.NotNil(t, resp.GetTransportParams())

	var m = &pb.PrefixTransportParams{}
	require.Nil(t, transports.UnmarshalAnypbTo(resp.GetTransportParams(), m))
	require.Equal(t, int32(-2), m.GetPrefixId())
	require.Equal(t, []byte("aaaa"), m.GetPrefix())
}

type mockPrefix struct {
	b  []byte
	id int32
}

func (mp *mockPrefix) Bytes() []byte {
	return mp.b
}

func (mp *mockPrefix) ID() prefix.PrefixID {
	return prefix.PrefixID(mp.id)
}

func (mp *mockPrefix) DstPort([]byte) uint16 {
	return 1024
}

func (mp *mockPrefix) FlushPolicy() int32 {
	return 1
}
