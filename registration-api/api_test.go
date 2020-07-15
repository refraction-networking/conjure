package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	zmq "github.com/pebbe/zmq4"
	pb "github.com/refraction-networking/gotapdance/protobuf"
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

func generateClientToAPIPayload() (c2API *pb.ClientToAPI, marshaledc2API []byte, encryptedc2s []byte) {
	generation := uint32(0)
	covert := "1.2.3.4:1234"
	v4Support := true
	v6Support := false
	c2s := pb.ClientToStation{
		DecoyListGeneration: &generation,
		CovertAddress:       &covert,
		V4Support:           &v4Support,
		V6Support:           &v6Support,
	}

	c2sBytes, err := proto.Marshal(&c2s)
	if err != nil {
		log.Fatalf("failed to marshal ClientToStation proto: expected nil, got %v", err)
	}

	block, _ := aes.NewCipher(secret)
	gcm, _ := cipher.NewGCM(block)
	iv := make([]byte, 12)
	encryptedc2s = gcm.Seal(nil, iv, c2sBytes, nil)

	c2API = &pb.ClientToAPI{
		Secret:              secret,
		RegistrationPayload: &c2s,
	}

	marshaledc2API, _ = proto.Marshal(c2API)

	return
}

func TestZMQPayloadGeneration(t *testing.T) {
	c2API, _, encryptedc2s := generateClientToAPIPayload()

	zmqPayload, err := generateZMQPayload(c2API)
	if err != nil {
		t.Fatalf("failed to generate ZMQ payload: expected nil, got %v", err)
	}

	if !bytes.Equal(zmqPayload[:SecretLength], secret) {
		t.Fatalf("secret in ZMQ payload doesn't match: expected %v, got %v", secret, zmqPayload[:32])
	}

	fsp := zmqPayload[SecretLength : SecretLength+6]
	var payloadLength uint16
	err = binary.Read(bytes.NewReader(fsp[:2]), binary.BigEndian, &payloadLength)
	if err != nil {
		t.Fatalf("failed to read payload length from FSP: expected nil, got %v", err)
	}

	if int(payloadLength) != len(encryptedc2s) {
		t.Fatalf("payload length in FSP doesn't math: expected %d, got %d", len(encryptedc2s), payloadLength)
	}

	var retrievedc2s pb.ClientToStation
	err = proto.Unmarshal(zmqPayload[SecretLength+6:], &retrievedc2s)
	if err != nil {
		t.Fatalf("failed to unmarshal ClientToStation from ZMQ payload: expected nil, got %v", err)
	}

	if retrievedc2s.GetDecoyListGeneration() != c2API.RegistrationPayload.GetDecoyListGeneration() {
		t.Fatalf("decoy list generation in retrieved ClientToStation doesn't match: expected %d, got %d", c2API.RegistrationPayload.GetDecoyListGeneration(), retrievedc2s.GetDecoyListGeneration())
	}

	if retrievedc2s.GetCovertAddress() != c2API.RegistrationPayload.GetCovertAddress() {
		t.Fatalf("covert address in retrieved ClientToStation doesn't match: expected %s, got %s", c2API.RegistrationPayload.GetCovertAddress(), retrievedc2s.GetCovertAddress())
	}

	if retrievedc2s.GetV4Support() != c2API.RegistrationPayload.GetV4Support() {
		t.Fatalf("v4 support in retrieved ClientToStation doesn't match: expected %v, got %v", c2API.RegistrationPayload.GetV4Support(), retrievedc2s.GetV4Support())
	}

	if retrievedc2s.GetV6Support() != c2API.RegistrationPayload.GetV6Support() {
		t.Fatalf("v6 support in retrieved ClientToStation doesn't match: expected %v, got %v", c2API.RegistrationPayload.GetV6Support(), retrievedc2s.GetV6Support())
	}
}

func TestCorrectRegistration(t *testing.T) {
	messageChan := make(chan []byte, 1)
	accepter := func(m []byte) error {
		messageChan <- m
		return nil
	}

	s := server{
		messageAccepter: accepter,
		logger:          logger,
	}

	_, body, _ := generateClientToAPIPayload()
	r := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	s.register(w, r)

	select {
	case <-messageChan:
		// We already tested the payload generation above, so here we're just confirming it arrives
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

	r := httptest.NewRequest("GET", "/register", nil)
	w := httptest.NewRecorder()

	s.register(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("response code mismatch: expected %d, got %d", http.StatusMethodNotAllowed, w.Code)
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

	_, body, _ := generateClientToAPIPayload()
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

	_, body, _ := generateClientToAPIPayload()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
		w := httptest.NewRecorder()
		s.register(w, r)
	}
}
