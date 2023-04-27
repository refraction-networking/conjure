package dnsregserver

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/refraction-networking/conjure/pkg/metrics"
	"github.com/refraction-networking/conjure/pkg/regprocessor"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

var (
	secretHex = []byte(`1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef`)
	secret    []byte
)

func init() {
	secret = make([]byte, regprocessor.SecretLength)
	_, err := hex.Decode(secret, secretHex)
	if err != nil {
		panic(err)
	}
}

func newDNSRegServer() DNSRegServer {
	return DNSRegServer{
		logger:  log.New(),
		metrics: metrics.NewMetrics(log.NewEntry(log.StandardLogger()), 5*time.Second),
	}
}

func generateC2SWrapperPayload() (c2API *pb.C2SWrapper, marshaledc2API []byte) {
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

	c2API = &pb.C2SWrapper{
		SharedSecret:        secret,
		RegistrationPayload: &c2s,
	}

	marshaledc2API, _ = proto.Marshal(c2API)

	return
}

type fakeRegistrar struct {
	fakeRegisterUnidirectionalFunc func(*pb.C2SWrapper, pb.RegistrationSource, []byte) error
	fakeRegisterBidirectionalFunc  func(*pb.C2SWrapper, pb.RegistrationSource, []byte) (*pb.RegistrationResponse, error)
}

func (f *fakeRegistrar) RegisterUnidirectional(c2sPayload *pb.C2SWrapper, regMethod pb.RegistrationSource, clientAddr []byte) error {
	if f.fakeRegisterUnidirectionalFunc != nil {
		return f.fakeRegisterUnidirectionalFunc(c2sPayload, regMethod, clientAddr)
	}
	return nil
}

func (f *fakeRegistrar) RegisterBidirectional(c2sPayload *pb.C2SWrapper, regMethod pb.RegistrationSource, clientAddr []byte) (*pb.RegistrationResponse, error) {
	if f.fakeRegisterBidirectionalFunc != nil {
		return f.fakeRegisterBidirectionalFunc(c2sPayload, regMethod, clientAddr)
	}
	return nil, nil
}

// Simulating a situation where ZMQ isn't functioning.
func TestBadAccepter(t *testing.T) {

	regFail := func(*pb.C2SWrapper, pb.RegistrationSource, []byte) error {
		return regprocessor.ErrRegProcessFailed
	}

	s := newDNSRegServer()
	s.processor = &fakeRegistrar{
		fakeRegisterUnidirectionalFunc: regFail,
	}

	_, body := generateC2SWrapperPayload()

	responsePayload, err := s.processRequest(body)

	if err != nil {
		t.Fatalf("processRequest returned error")
	}

	response := &pb.DnsResponse{}
	err = proto.Unmarshal(responsePayload, response)
	if err != nil {
		t.Fatalf("response unmarshal failed")
	}

	if response.GetSuccess() {
		t.Fatalf("response should indicate that registration was NOT successful")
	}
}

func TestCorrectUnidirectionalDNS(t *testing.T) {
	clientIP := "1.2.3.4"

	fakeUniRegFunc := func(c2sPayload *pb.C2SWrapper, regMethod pb.RegistrationSource, clientAddr []byte) error {
		if regMethod != pb.RegistrationSource_DNS {
			t.Fatalf("incorrect registration method passed to processor")
		}
		return nil
	}

	s := newDNSRegServer()
	s.processor = &fakeRegistrar{
		fakeRegisterUnidirectionalFunc: fakeUniRegFunc,
	}

	c2sPayload, _ := generateC2SWrapperPayload()
	regSrc := pb.RegistrationSource_DNS
	c2sPayload.RegistrationSource = &regSrc
	c2sPayload.RegistrationAddress = net.ParseIP(clientIP).To16()
	body, _ := proto.Marshal(c2sPayload)

	responsePayload, err := s.processRequest(body)

	if err != nil {
		t.Fatalf("processRequest returned error: %v", err)
	}

	response := &pb.DnsResponse{}
	err = proto.Unmarshal(responsePayload, response)
	if err != nil {
		t.Fatalf("response unmarshal failed: %v", err)
	}

	if !response.GetSuccess() {
		t.Fatalf("response should indicate that registration was successful")
	}
}

func TestCorrectBidirectionalDNS(t *testing.T) {
	fakeV4Phantom := "9.8.7.6"
	fakeV6Phantom := "fbdc:8e7d:872c:ce49:5470:8223:db34:7d67"

	clientIP := "1.2.3.4"

	ccGen := uint32(1111)

	fakeBdRegFunc := func(c2sPayload *pb.C2SWrapper, regMethod pb.RegistrationSource, clientAddr []byte) (*pb.RegistrationResponse, error) {
		if regMethod != pb.RegistrationSource_BidirectionalDNS {
			t.Fatalf("incorrect registration method passed to processor")
		}

		v4int := binary.BigEndian.Uint32(net.ParseIP(fakeV4Phantom).To4())
		port := uint32(443)
		return &pb.RegistrationResponse{
			Ipv4Addr: &v4int,
			Ipv6Addr: net.ParseIP(fakeV6Phantom),
			DstPort:  &port,
		}, nil
	}

	s := newDNSRegServer()
	s.processor = &fakeRegistrar{
		fakeRegisterBidirectionalFunc: fakeBdRegFunc,
	}
	s.latestCCGen = ccGen

	c2sPayload, _ := generateC2SWrapperPayload()
	regSrc := pb.RegistrationSource_BidirectionalDNS
	c2sPayload.RegistrationSource = &regSrc
	c2sPayload.RegistrationAddress = net.ParseIP(clientIP).To16()
	body, _ := proto.Marshal(c2sPayload)

	fmt.Println(c2sPayload.SharedSecret)

	responsePayload, err := s.processRequest(body)

	if err != nil {
		t.Fatalf("processRequest returned error: %v", err)
	}

	response := &pb.DnsResponse{}
	err = proto.Unmarshal(responsePayload, response)
	if err != nil {
		t.Fatalf("response unmarshal failed: %v", err)
	}

	if !response.GetSuccess() {
		t.Fatalf("response should indicate that registration was successful")
	}

	resp := response.GetBidirectionalResponse()

	respIpv4 := make(net.IP, 4)
	binary.BigEndian.PutUint32(respIpv4, resp.GetIpv4Addr())

	v4RespStr := net.IP(respIpv4).To4().String()

	if v4RespStr != fakeV4Phantom {
		t.Fatal("response ip incorrect")
	}

	respIpv6 := resp.GetIpv6Addr()

	if net.IP(respIpv6).String() != fakeV6Phantom {
		t.Fatal("response ip incorrect")
	}
}

func TestCorrectClientConfGen(t *testing.T) {
	clientIP := "1.2.3.4"

	ccGenUpToDate := uint32(1111)
	oldCCGen := uint32(1110)

	if ccGenUpToDate == oldCCGen {
		t.FailNow()
	}

	fakeBdRegFunc := func(c2sPayload *pb.C2SWrapper, regMethod pb.RegistrationSource, clientAddr []byte) (*pb.RegistrationResponse, error) {
		if regMethod != pb.RegistrationSource_BidirectionalDNS {
			t.Fatalf("incorrect registration method passed to processor")
		}

		if c2sPayload.RegistrationPayload.GetDecoyListGeneration() != oldCCGen {
			t.Fatalf("clientConf generation should not be modified for DNS registrar")
		}

		return &pb.RegistrationResponse{}, nil
	}

	s := newDNSRegServer()
	s.processor = &fakeRegistrar{
		fakeRegisterBidirectionalFunc: fakeBdRegFunc,
	}
	s.latestCCGen = ccGenUpToDate

	c2sPayload, _ := generateC2SWrapperPayload()
	regSrc := pb.RegistrationSource_BidirectionalDNS
	c2sPayload.RegistrationSource = &regSrc
	c2sPayload.RegistrationAddress = net.ParseIP(clientIP).To16()
	c2sPayload.RegistrationPayload.DecoyListGeneration = &oldCCGen
	body, _ := proto.Marshal(c2sPayload)

	fmt.Println(c2sPayload.SharedSecret)

	responsePayload, err := s.processRequest(body)

	if err != nil {
		t.Fatalf("processRequest returned error: %v", err)
	}

	response := &pb.DnsResponse{}
	err = proto.Unmarshal(responsePayload, response)
	if err != nil {
		t.Fatalf("response unmarshal failed: %v", err)
	}

	if !response.GetClientconfOutdated() {
		t.Fatalf("response should indicate that client ClientConf is outdated")
	}

}
