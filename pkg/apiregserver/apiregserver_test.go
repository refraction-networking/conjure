package apiregserver

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	zmq "github.com/pebbe/zmq4"
	"github.com/refraction-networking/conjure/pkg/regprocessor"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
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

func TestIncorrectMethod(t *testing.T) {
	s := APIRegServer{
		logger:      log.New(),
		logClientIP: true,
	}

	r := httptest.NewRequest("GET", "/register", nil)
	w := httptest.NewRecorder()

	s.register(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("response code mismatch: expected %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestParseIP(t *testing.T) {
	resp := parseIP("127.0.0.1")
	if resp.String() != "127.0.0.1" {
		t.Fatalf("parseIP unable to parse raw ipv4 address")
	}

	resp = parseIP("127.0.0.1:443")
	if resp.String() != "127.0.0.1" {
		t.Fatalf("parseIP unable to parse raw ipv4 address with port")
	}

	resp = parseIP("2001::1")
	if resp.String() != "2001::1" {
		t.Fatalf("parseIP unable to parse raw ipv6 address")
	}

	resp = parseIP("[2001::1]")
	if resp != nil {
		t.Fatal("parseIP unable to parse ipv6 address with brackets")
	}

	resp = parseIP("[2001::1]:80")
	if resp.String() != "2001::1" {
		t.Fatal("parseIP unable to parse ipv6 address with port")
	}

}

func TestEmptyBody(t *testing.T) {
	s := APIRegServer{
		logger:      log.New(),
		logClientIP: true,
	}

	r := httptest.NewRequest("POST", "/register", nil)
	w := httptest.NewRecorder()

	s.register(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("response code mismatch: expected %d, got %d", http.StatusBadRequest, w.Code)
	}
}

// Simulating a situation where ZMQ isn't functioning.
func TestBadAccepter(t *testing.T) {

	regFail := func(*pb.C2SWrapper, pb.RegistrationSource, []byte) error {
		return regprocessor.ErrRegProcessFailed
	}

	s := APIRegServer{
		processor: &fakeRegistrar{
			fakeRegisterUnidirectionalFunc: regFail,
		},
		logger:      log.New(),
		logClientIP: true,
	}

	_, body := generateC2SWrapperPayload()
	r := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.register(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("response code mismatch: expected %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// Basic benchmark of registration capacity. Note that this **does** purposely
// include a dependency on ZMQ since we'll be blocking on the library calls
// during the handler, so while it doesn't represent only our code it represents
// a realistic situation.
func BenchmarkRegistration(b *testing.B) {
	regMutex := sync.Mutex{}
	sock, err := zmq.NewSocket(zmq.PUB)
	if err != nil {
		log.Fatalln("failed to set up ZMQ socket:", err)
	}

	err = sock.Bind("tcp://*:5589")
	if err != nil {
		log.Fatalln("failed to bind ZMQ socket:", err)
	}

	regSim := func(c2sPayload *pb.C2SWrapper, regMethod pb.RegistrationSource, clientAddr []byte) error {
		c2sBytes, err := proto.Marshal(c2sPayload)
		if err != nil {
			log.Fatalln("failed to marshal payload: ", err)
		}

		regMutex.Lock()
		_, err = sock.SendBytes(c2sBytes, zmq.DONTWAIT)
		regMutex.Unlock()

		if err != nil {
			log.Fatalln("failed to send payload: ", err)
		}
		return nil
	}

	s := APIRegServer{
		processor: &fakeRegistrar{
			fakeRegisterUnidirectionalFunc: regSim,
		},
		logger:      log.New(),
		logClientIP: true,
	}

	_, body := generateC2SWrapperPayload()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
		w := httptest.NewRecorder()
		s.register(w, r)
	}
}

func TestAPIGetClientAddr(t *testing.T) {

	req, err := http.NewRequest("GET", "http://example.com", nil)
	require.Nil(t, err)

	req.RemoteAddr = "10.0.0.0"
	require.Equal(t, "10.0.0.0", getRemoteAddr(req))

	req.Header.Add("X-Forwarded-For", "192.168.1.1")
	require.Equal(t, "192.168.1.1", getRemoteAddr(req))

	req.Header.Set("X-Forwarded-For", "127.0.0.1, 192.168.0.0")
	require.Equal(t, "127.0.0.1", getRemoteAddr(req))

	req.Header.Set("X-Forwarded-For", "127.0.0.1,192.168.0.0")
	require.Equal(t, "127.0.0.1", getRemoteAddr(req))
}

func TestCorrectUnidirectionalAPI(t *testing.T) {
	originalIP := "1.2.3.4"
	updatedIP := "4.3.2.1"

	fakeUniRegFunc := func(c2sPayload *pb.C2SWrapper, regMethod pb.RegistrationSource, clientAddr []byte) error {
		correctIpBytes := []byte(net.ParseIP(updatedIP))
		if !reflect.DeepEqual(clientAddr, correctIpBytes) {
			t.Fatalf("incorrect client IP passed into regprocessor")
		}

		return nil
	}

	s := APIRegServer{
		processor: &fakeRegistrar{
			fakeRegisterUnidirectionalFunc: fakeUniRegFunc,
		},
		logger:      log.New(),
		logClientIP: true,
	}

	// Client sends to station v4 or v6, shared secret, etc.
	c2sPayload, _ := generateC2SWrapperPayload() // v4 support
	regSrc := pb.RegistrationSource_API
	c2sPayload.RegistrationSource = &regSrc
	c2sPayload.RegistrationAddress = net.ParseIP(originalIP).To16()
	body, _ := proto.Marshal(c2sPayload)

	fmt.Println(c2sPayload.SharedSecret)

	r := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	r.RemoteAddr = updatedIP

	s.registerBidirectional(w, r)
	// Test for the new pb coming back
	// w should respond with HTTP StatusOK, meaning it got something back
	if w.Code != http.StatusOK {
		t.Fatalf("response code mismatch: expected %d, got %d", http.StatusOK, w.Code)
	}
}

func TestCorrectBidirectionalAPI(t *testing.T) {
	fakeV4Phantom := "9.8.7.6"
	fakeV6Phantom := "fbdc:8e7d:872c:ce49:5470:8223:db34:7d67"

	originalIP := "1.2.3.4"
	updatedIP := "4.3.2.1"

	fakeBdRegFunc := func(c2sPayload *pb.C2SWrapper, regMethod pb.RegistrationSource, clientAddr []byte) (*pb.RegistrationResponse, error) {
		correctIpBytes := []byte(net.ParseIP(updatedIP))
		if !reflect.DeepEqual(clientAddr, correctIpBytes) {
			t.Fatalf("incorrect client IP passed into regprocessor")
		}

		v4int := binary.BigEndian.Uint32(net.ParseIP(fakeV4Phantom).To4())
		port := uint32(443)
		return &pb.RegistrationResponse{
			Ipv4Addr: &v4int,
			Ipv6Addr: net.ParseIP(fakeV6Phantom),
			Port:     &port,
		}, nil
	}

	s := APIRegServer{
		processor: &fakeRegistrar{
			fakeRegisterBidirectionalFunc: fakeBdRegFunc,
		},
		logger:      log.New(),
		logClientIP: true,
	}

	c2sPayload, _ := generateC2SWrapperPayload()
	regSrc := pb.RegistrationSource_BidirectionalAPI
	c2sPayload.RegistrationSource = &regSrc
	c2sPayload.RegistrationAddress = net.ParseIP(originalIP).To16()
	body, _ := proto.Marshal(c2sPayload)

	fmt.Println(c2sPayload.SharedSecret)

	r := httptest.NewRequest("POST", "/register-bidriectional", bytes.NewReader(body))
	w := httptest.NewRecorder()

	r.RemoteAddr = updatedIP

	s.registerBidirectional(w, r)
	respPayload := w.Result()

	// Test for the new pb coming back
	// w should respond with HTTP StatusOK, meaning it got something back
	if w.Code != http.StatusOK {
		t.Fatalf("response code mismatch: expected %d, got %d", http.StatusOK, w.Code)
	}

	defer respPayload.Body.Close()
	// resp stores the server response from w
	// Read (desearialize) resp's body into type []byte
	bodyBytes, err := io.ReadAll(respPayload.Body)
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal
	resp := &pb.RegistrationResponse{}
	if err = proto.Unmarshal(bodyBytes, resp); err != nil {
		t.Fatalf("Unable to unmarshal RegistrationResponse protobuf")
	}

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

func TestBidirectionalAPIClientConf(t *testing.T) {
	testCCGeneration := uint32(1153)

	testCC := &pb.ClientConf{
		Generation: &testCCGeneration,
	}

	fakeBdRegFunc := func(c2sPayload *pb.C2SWrapper, regMethod pb.RegistrationSource, clientAddr []byte) (*pb.RegistrationResponse, error) {
		if c2sPayload.RegistrationPayload.GetDecoyListGeneration() < testCCGeneration {
			t.Fatalf("outdated clientconf in c2s not updated by API before sending to be processed")
		}

		return &pb.RegistrationResponse{}, nil
	}

	s := APIRegServer{
		processor: &fakeRegistrar{
			fakeRegisterBidirectionalFunc: fakeBdRegFunc,
		},
		latestClientConf: testCC,
		logger:           log.New(),
		logClientIP:      true,
	}

	// Client sends to station v4 or v6, shared secret, etc.
	c2sPayload, _ := generateC2SWrapperPayload() // v4 support
	regSrc := pb.RegistrationSource_BidirectionalAPI
	c2sPayload.RegistrationSource = &regSrc
	outdatedVersion := uint32(0)
	c2sPayload.RegistrationPayload.DecoyListGeneration = &outdatedVersion
	body, _ := proto.Marshal(c2sPayload)

	r := httptest.NewRequest("POST", "/register-bidriectional", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.registerBidirectional(w, r)
	respPayload := w.Result()

	// Test for the new pb coming back
	// w should respond with HTTP StatusOK, meaning it got something back
	if w.Code != http.StatusOK {
		t.Fatalf("response code mismatch: expected %d, got %d", http.StatusOK, w.Code)
	}

	defer respPayload.Body.Close()
	// resp stores the server response from w
	// Read (desearialize) resp's body into type []byte
	bodyBytes, err := io.ReadAll(respPayload.Body)
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal
	resp := &pb.RegistrationResponse{}
	if err = proto.Unmarshal(bodyBytes, resp); err != nil {
		t.Fatalf("Unable to unmarshal RegistrationResponse protobuf")
	}

	if resp.ClientConf == nil {
		t.Fatalf("server client conf not returned in registration response")
	}
}

func TestCompareCCGen(t *testing.T) {
	testCCGeneration := uint32(1153)

	testCC := &pb.ClientConf{
		Generation: &testCCGeneration,
	}

	s := APIRegServer{
		latestClientConf: testCC,
		logger:           log.New(),
		logClientIP:      true,
	}

	cc := s.compareClientConfGen(testCCGeneration - 1)
	if cc == nil {
		t.Errorf("should include update for generation numbers less than server current")
	}

	cc = s.compareClientConfGen(testCCGeneration)
	if cc != nil {
		t.Errorf("should NOT include update for generation numbers equal to server current")
	}

	cc = s.compareClientConfGen(testCCGeneration + 1)
	if cc != nil {
		t.Errorf("should NOT include update for generation numbers greater than server current")
	}
}