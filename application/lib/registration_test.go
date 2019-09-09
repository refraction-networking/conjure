package lib

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"net"
	"testing"
	"time"
)

func mockReceiveFromDetector() (pb.ClientToStation, ConjureSharedKeys, [1]byte) {
	clientToStationBytes := []byte{
		0x10, 0x9a, 0x04, 0x18, 0x0b, 0xa2, 0x01, 0x0e, 0x35, 0x32, 0x2e, 0x34, 0x34, 0x2e, 0x37,
		0x33, 0x2e, 0x36, 0x3a, 0x34, 0x34, 0x33, 0xb0, 0x01, 0x00, 0xa2, 0x06, 0x01, 0x00}
	sharedSecret := []byte{
		0x54, 0x14, 0xc7, 0x34, 0xad, 0x5d, 0xc5, 0x3e, 0x6b, 0x56, 0xa7, 0xbb, 0x47, 0xce, 0x69, 0x5a,
		0x14, 0xa3, 0xef, 0x07, 0x6a, 0x3d, 0x5a, 0xce, 0x9c, 0xbf, 0x3b, 0x4d, 0x12, 0x70, 0x6b, 0x73}
	flags := [1]byte{0x01}

	clientToStation := &pb.ClientToStation{}
	err := proto.Unmarshal(clientToStationBytes, clientToStation)
	if err != nil {
		fmt.Printf("Failed to unmarshal ClientToStation protobuf\n")
	}

	conjureKeys, err := GenSharedKeys(sharedSecret)

	return *clientToStation, conjureKeys, flags
}

func testEqualRegistrations(reg1 *DecoyRegistration, reg2 *DecoyRegistration) bool {
	return true
}

func TestCreateDecoyRegistration(t *testing.T) {
	rm := NewRegistrationManager()

	c2s, keys, flags := mockReceiveFromDetector()

	newReg, err := rm.NewRegistration(&c2s, &keys, flags)
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	expectedReg := DecoyRegistration{}

	if !testEqualRegistrations(newReg, &expectedReg) {
		t.Fatalf("Bad registration Created")
	}
}

func TestLivenessCheck(t *testing.T) {

	phantomAddr := net.ParseIP("54.44.73.6")
	reg := DecoyRegistration{
		DarkDecoy: &phantomAddr,
	}

	if reg.PhantomIsLive() != true {
		t.Fatalf("Live host seen as non-responsive")
	}

	// // Is there any test address we know will never respond?
	// unroutableIP := net.ParseIP("0.0.0.0")
	// reg.DarkDecoy = &unroutableIP

	// if reg.PhantomIsLive() != false {
	// 	t.Fatalf("Non-Responsive host seen as Live")
	// }
}

func TestManagerFunctionality(t *testing.T) {
	rm := NewRegistrationManager()

	c2s, keys, flags := mockReceiveFromDetector()

	newReg, err := rm.NewRegistration(&c2s, &keys, flags)
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	rm.AddRegistration(newReg)

	storedReg := rm.CheckRegistration(newReg.DarkDecoy)

	fmt.Printf("%#v\n", storedReg)
}

func TestRegisterForDetector(t *testing.T) {
	darkDecoyAddr := net.ParseIP("1.2.3.4")
	reg := DecoyRegistration{
		DarkDecoy: &darkDecoyAddr,
	}

	client, err := getRedisClient()
	if err != nil {
		t.Fatalf("couldn't connect to redis\n")
	}
	pubsub := client.Subscribe(DETECTOR_REG_CHANNEL)

	// go channel that receives published messages
	channel := pubsub.Channel()

	// send message to redis pubsub, wait, then close subscriber & channel
	registerForDetector(&reg)

	time.AfterFunc(time.Millisecond*500, func() {
		_ = pubsub.Close()
	})

	// check message
	msg := <-channel
	if msg == nil {
		t.Fatalf("no messages received\n")
	} else {
		t.Logf("Read %s from subscriber\n", msg.Payload)
	}

	// check IP equality
	if reg.DarkDecoy.Equal(net.ParseIP(msg.Payload)) == false {
		t.Fatalf("Expected %v, got %v", reg.DarkDecoy, msg.Payload)
	}
}
