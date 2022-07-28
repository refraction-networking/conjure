package regprocessor

import (
	"encoding/hex"
	"log"
	"net"
	"testing"

	"google.golang.org/protobuf/proto"

	zmq "github.com/pebbe/zmq4"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

var (
	secretHex = []byte(`1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef`)
	secret    []byte
)

func init() {
	secret = make([]byte, SecretLength)
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
		V6Support:           &falseBool,
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

func TestC2SWrapperProcessing(t *testing.T) {
	c2API, _ := generateC2SWrapperPayload()

	zmqPayload, err := processC2SWrapper(c2API, []byte(net.ParseIP("127.0.0.1").To16()), pb.RegistrationSource_API)
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
	zmqPayload, err = processC2SWrapper(c2API, []byte(net.ParseIP("127.0.0.1").To16()), pb.RegistrationSource_API)
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

	s := RegProcessor{
		sock: sock,
	}

	body, _ := generateC2SWrapperPayload()
	b.ResetTimer()

	sourceIP := net.ParseIP("1.2.3.4:443")

	for i := 0; i < b.N; i++ {
		s.RegisterUnidirectional(body, []byte(sourceIP), pb.RegistrationSource_API)
	}
}
