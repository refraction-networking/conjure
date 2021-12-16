package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	zmq "github.com/pebbe/zmq4"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/stretchr/testify/require"
)

var (
	secretHex = []byte(`1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef`)
	secret    []byte

	logger = log.New(os.Stdout, "[API] ", log.Ldate|log.Lmicroseconds)
)

func init() {
	secret = make([]byte, SecretLength)
	hex.Decode(secret, secretHex)
}

func generateC2SWrapperPayload() (c2API *pb.C2SWrapper, marshaledc2API []byte) {
	generation := uint32(0)
	covert := "1.2.3.4:1234"

	// We need pointers to bools. This is nasty D:
	true_bool := true
	false_bool := false

	c2s := pb.ClientToStation{
		DecoyListGeneration: &generation,
		CovertAddress:       &covert,
		V4Support:           &true_bool,
		V6Support:           &false_bool,
		Flags: &pb.RegistrationFlags{
			ProxyHeader: &true_bool,
			Use_TIL:     &true_bool,
			UploadOnly:  &false_bool,
		},
	}

	c2API = &pb.C2SWrapper{
		SharedSecret:        secret,
		RegistrationPayload: &c2s,
	}

	marshaledc2API, _ = proto.Marshal(c2API)

	return
}

func TestC2SWrapperProcessing(t *testing.T) {
	c2API, _ := generateC2SWrapperPayload()
	messageChan := make(chan []byte, 1)
	accepter := func(m []byte) error {
		messageChan <- m
		return nil
	}

	s := server{
		messageAccepter: accepter,
		logger:          logger,
	}

	zmqPayload, err := s.processC2SWrapper(c2API, []byte(net.ParseIP("127.0.0.1").To16()))
	if err != nil {
		t.Fatalf("failed to generate ZMQ payload: expected nil, got %v", err)
	}

	var retrievedPayload pb.C2SWrapper
	err = proto.Unmarshal(zmqPayload, &retrievedPayload)
	if err != nil {
		t.Fatalf("failed to unmarshal ClientToStation from ZMQ payload: expected nil, got %v", err)
	}

	if retrievedPayload.RegistrationPayload.GetDecoyListGeneration() != c2API.RegistrationPayload.GetDecoyListGeneration() {
		t.Fatalf("decoy list generation in retrieved ClientToStation doesn't match: expected %d, got %d", c2API.RegistrationPayload.GetDecoyListGeneration(), retrievedPayload.RegistrationPayload.GetDecoyListGeneration())
	}

	if retrievedPayload.RegistrationPayload.GetCovertAddress() != c2API.RegistrationPayload.GetCovertAddress() {
		t.Fatalf("covert address in retrieved ClientToStation doesn't match: expected %s, got %s", c2API.RegistrationPayload.GetCovertAddress(), retrievedPayload.RegistrationPayload.GetCovertAddress())
	}

	if retrievedPayload.RegistrationPayload.GetV4Support() != c2API.RegistrationPayload.GetV4Support() {
		t.Fatalf("v4 support in retrieved ClientToStation doesn't match: expected %v, got %v", c2API.RegistrationPayload.GetV4Support(), retrievedPayload.RegistrationPayload.GetV4Support())
	}

	if retrievedPayload.RegistrationPayload.GetV6Support() != c2API.RegistrationPayload.GetV6Support() {
		t.Fatalf("v6 support in retrieved ClientToStation doesn't match: expected %v, got %v", c2API.RegistrationPayload.GetV6Support(), retrievedPayload.RegistrationPayload.GetV6Support())
	}

	if net.IP(retrievedPayload.GetRegistrationAddress()).String() != "127.0.0.1" {
		t.Fatalf("source address in retrieved C2Swrapper doesn't match: expected %v, got %v", "127.0.0.1", net.IP(retrievedPayload.GetRegistrationAddress()).String())
	}

	if retrievedPayload.GetRegistrationSource() != pb.RegistrationSource_API {
		t.Fatalf("Registration source in retrieved C2Swrapper doesn't match: expected %v, got %v", pb.RegistrationSource_API, retrievedPayload.GetRegistrationSource())
	}

	altSource := pb.RegistrationSource_DetectorPrescan
	c2API.RegistrationSource = &altSource
	zmqPayload, err = s.processC2SWrapper(c2API, []byte(net.ParseIP("127.0.0.1").To16()))
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

func TestCorrectRegistrationAPI(t *testing.T) {
	messageChan := make(chan []byte, 1)
	accepter := func(m []byte) error {
		messageChan <- m
		return nil
	}

	s := server{
		messageAccepter: accepter,
		logger:          logger,
	}
	s.logClientIP = true

	c2API, _ := generateC2SWrapperPayload()
	regSrc := pb.RegistrationSource_API
	c2API.RegistrationSource = &regSrc
	c2API.RegistrationAddress = net.ParseIP("8.8.8.8").To16()
	body, _ := proto.Marshal(c2API)

	r := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.register(w, r)

	select {
	case m := <-messageChan:
		// We already tested the payload generation above, so here we're just
		// confirming it arrives with the correct modifications
		payload := &pb.C2SWrapper{}
		if err := proto.Unmarshal(m, payload); err != nil {
			t.Fatalf("Bad C2Swrapper returned")
		}

		// If the Address isn't re-written for API registrar source throw error
		if net.IP(payload.GetRegistrationAddress()).String() == "8.8.8.8" {
			t.Fatalf("Registration Address should be overwritten for API registrar")
		}

	case <-time.After(100 * time.Millisecond):
		t.Fatalf("timed out waiting for message from endpoint")
	}

	if w.Code != http.StatusNoContent {
		t.Fatalf("response code mismatch: expected %d, got %d", http.StatusNoContent, w.Code)
	}

}

func TestCorrectRegistrationPrescan(t *testing.T) {
	messageChan := make(chan []byte, 1)
	accepter := func(m []byte) error {
		messageChan <- m
		return nil
	}

	s := server{
		messageAccepter: accepter,
		logger:          logger,
	}
	s.logClientIP = true
	c2API, _ := generateC2SWrapperPayload()
	regSrc := pb.RegistrationSource_DetectorPrescan
	c2API.RegistrationSource = &regSrc
	c2API.RegistrationAddress = net.ParseIP("8.8.8.8").To16()
	body, _ := proto.Marshal(c2API)

	r := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.register(w, r)

	select {
	case m := <-messageChan:
		// We already tested the payload generation above, so here we're just
		// confirming it arrives with the correct modifications
		payload := &pb.C2SWrapper{}
		if err := proto.Unmarshal(m, payload); err != nil {
			t.Fatalf("Bad C2Swrapper returned")
		}

		// If the Address is re-written for DetectorPreScan registrar source throw error
		if net.IP(payload.GetRegistrationAddress()).String() != "8.8.8.8" {
			t.Fatalf("Registration Address should not be overwritten for API registrar")
		}

	case <-time.After(100 * time.Millisecond):
		t.Fatalf("timed out waiting for message from endpoint")
	}

	if w.Code != http.StatusNoContent {
		t.Fatalf("response code mismatch: expected %d, got %d", http.StatusNoContent, w.Code)
	}
}

func TestIncorrectMethod(t *testing.T) {
	s := server{
		messageAccepter: nil,
		logger:          logger,
	}
	s.logClientIP = true

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
	s := server{
		messageAccepter: nil,
		logger:          logger,
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
	accepter := func(m []byte) error {
		return fmt.Errorf("simulated error")
	}

	s := server{
		messageAccepter: accepter,
		logger:          logger,
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
	sock, err := zmq.NewSocket(zmq.PUB)
	if err != nil {
		log.Fatalln("failed to set up ZMQ socket:", err)
	}

	err = sock.Bind("tcp://*:5599")
	if err != nil {
		log.Fatalln("failed to bind ZMQ socket:", err)
	}

	s := server{
		logger: log.New(ioutil.Discard, "", 0),
		sock:   sock,
	}
	s.messageAccepter = s.sendToZMQ

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

func TestCorrectBidirectionalAPI(t *testing.T) {
	// Set subnet environment
	os.Setenv("PHANTOM_SUBNET_LOCATION", "../application/lib/test/phantom_subnets.toml")

	messageChan := make(chan []byte, 1)
	accepter := func(m []byte) error {
		messageChan <- m
		return nil
	}

	generation_957 := uint16(957)

	// Create a server with the channel created above
	s := server{
		messageAccepter: accepter,
		logger:          logger,
	}
	s.logClientIP = true

	s.config.BidirectionalAPIGen = generation_957

	// Client sends to station v4 or v6, shared secret, etc.
	c2API, _ := generateC2SWrapperPayload() // v4 support
	regSrc := pb.RegistrationSource_BidirectionalAPI
	c2API.RegistrationSource = &regSrc
	c2API.RegistrationAddress = net.ParseIP("8.8.8.8").To16()
	body, _ := proto.Marshal(c2API)

	fmt.Println(c2API.SharedSecret)

	r := httptest.NewRequest("POST", "/register-bidriectional", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.initPhantomSelector()
	s.registerBidirectional(w, r)
	resp := w.Result()

	select {
	case m := <-messageChan:
		// We already tested the payload generation above, so here we're just
		// confirming it arrives with the correct modifications
		payload := &pb.C2SWrapper{}
		if err := proto.Unmarshal(m, payload); err != nil {
			t.Fatalf("Bad C2Swrapper returned")
		}

		// If the Address isn't re-written for API registrar source throw error
		if net.IP(payload.GetRegistrationAddress()).String() == "8.8.8.8" {
			t.Fatalf("Registration Address should be overwritten for API registrar")
		}

	case <-time.After(100 * time.Millisecond):
		t.Fatalf("timed out waiting for message from endpoint")
	}

	// Test for the new pb coming back
	// w should respond with HTTP StatusOK, meaning it got something back
	if w.Code != http.StatusOK {
		t.Fatalf("response code mismatch: expected %d, got %d", http.StatusOK, w.Code)
	}

	defer resp.Body.Close()
	// resp stores the server response from w
	// Read (desearialize) resp's body into type []byte
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal
	resp_payload := &pb.RegistrationResponse{}
	if err = proto.Unmarshal(bodyBytes, resp_payload); err != nil {
		t.Fatalf("Unable to unmarshal RegistrationResponse protobuf")
	}

	t.Log(*resp_payload.Ipv4Addr)
}

func TestBidirectionalAPIClientConf(t *testing.T) {
	// Set subnet environment
	os.Setenv("PHANTOM_SUBNET_LOCATION", "../application/lib/test/phantom_subnets.toml")

	messageChan := make(chan []byte, 1)
	accepter := func(m []byte) error {
		messageChan <- m
		return nil
	}

	generation_1028 := uint16(1028)

	// Create a server with the channel created above
	s := server{
		messageAccepter: accepter,
		logger:          logger,
	}
	s.logClientIP = true

	s.config.BidirectionalAPIGen = generation_1028
	s.config.ClientConfPath = "/opt/conjure/sysconfig/ClientConf"

	// Client sends to station v4 or v6, shared secret, etc.
	c2API, _ := generateC2SWrapperPayload() // v4 support
	regSrc := pb.RegistrationSource_BidirectionalAPI
	c2API.RegistrationSource = &regSrc
	c2API.RegistrationAddress = net.ParseIP("8.8.8.8").To16()
	body, _ := proto.Marshal(c2API)

	r := httptest.NewRequest("POST", "/register-bidriectional", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.initPhantomSelector()
	s.registerBidirectional(w, r)
	resp := w.Result()

	select {
	case m := <-messageChan:
		// We already tested the payload generation above, so here we're just
		// confirming it arrives with the correct modifications
		payload := &pb.C2SWrapper{}
		if err := proto.Unmarshal(m, payload); err != nil {
			t.Fatalf("Bad C2Swrapper returned")
		}

		// If the Address isn't re-written for API registrar source throw error
		if net.IP(payload.GetRegistrationAddress()).String() == "8.8.8.8" {
			t.Fatalf("Registration Address should be overwritten for API registrar")
		}

	case <-time.After(100 * time.Millisecond):
		t.Fatalf("timed out waiting for message from endpoint")
	}

	// Test for the new pb coming back
	// w should respond with HTTP StatusOK, meaning it got something back
	if w.Code != http.StatusOK {
		t.Fatalf("response code mismatch: expected %d, got %d", http.StatusOK, w.Code)
	}

	defer resp.Body.Close()
	// resp stores the server response from w
	// Read (desearialize) resp's body into type []byte
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	// Unmarshal
	resp_payload := &pb.RegistrationResponse{}
	if err = proto.Unmarshal(bodyBytes, resp_payload); err != nil {
		t.Fatalf("Unable to unmarshal RegistrationResponse protobuf")
	}

	t.Log(*resp_payload.Ipv4Addr)
	t.Log(*resp_payload.ClientConf)
}
