package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

func TestZMQPayloadGeneration(t *testing.T) {
	secretHex := []byte(`1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef`)
	secret := make([]byte, SecretLength)
	hex.Decode(secret, secretHex)

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
		t.Fatalf("failed to marshal ClientToStation proto: expected nil, got %v", err)
	}

	block, _ := aes.NewCipher(secret)
	gcm, _ := cipher.NewGCM(block)
	iv := make([]byte, 12)
	encryptedc2s := gcm.Seal(nil, iv, c2sBytes, nil)

	c2API := pb.ClientToAPI{
		Secret:              secret,
		RegistrationPayload: &c2s,
	}

	zmqPayload, err := generateZMQPayload(&c2API)
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

	if retrievedc2s.GetDecoyListGeneration() != generation {
		t.Fatalf("decoy list generation in retrieved ClientToStation doesn't match: expected %d, got %d", generation, retrievedc2s.GetDecoyListGeneration())
	}

	if retrievedc2s.GetCovertAddress() != covert {
		t.Fatalf("covert address in retrieved ClientToStation doesn't match: expected %s, got %s", covert, retrievedc2s.GetCovertAddress())
	}

	if retrievedc2s.GetV4Support() != v4Support {
		t.Fatalf("v4 support in retrieved ClientToStation doesn't match: expected %v, got %v", v4Support, retrievedc2s.GetV4Support())
	}

	if retrievedc2s.GetV6Support() != v6Support {
		t.Fatalf("v6 support in retrieved ClientToStation doesn't match: expected %v, got %v", v6Support, retrievedc2s.GetV6Support())
	}
}
