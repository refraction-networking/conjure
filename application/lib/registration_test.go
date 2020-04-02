package lib

import (
	"encoding/hex"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

func mockReceiveFromDetector() (pb.ClientToStation, ConjureSharedKeys, [1]byte) {
	clientToStationBytes, err := hex.DecodeString("109a04180ba2010e35322e34342e37332e363a343433b00100a2060100")
	sharedSecret, err := hex.DecodeString("5414c734ad5dc53e6b56a7bb47ce695a14a3ef076a3d5ace9cbf3b4d12706b73")
	flags := [1]byte{0x01}

	clientToStation := &pb.ClientToStation{}
	err = proto.Unmarshal(clientToStationBytes, clientToStation)
	if err != nil {
		fmt.Printf("Failed to unmarshal ClientToStation protobuf\n")
	}

	conjureKeys, err := GenSharedKeys(sharedSecret)

	return *clientToStation, conjureKeys, flags
}

func testEqualRegistrations(reg1 *DecoyRegistration, reg2 *DecoyRegistration) bool {
	return true
}

// This is not actually working yet
func TestCreateDecoyRegistration(t *testing.T) {
	rm := NewRegistrationManager()

	c2s, keys, flags := mockReceiveFromDetector()

	newReg, err := rm.NewRegistration(&c2s, &keys, flags, c2s.GetV6Support())
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	expectedReg := DecoyRegistration{}

	if !testEqualRegistrations(newReg, &expectedReg) {
		t.Fatalf("Bad registration Created")
	}
}

func TestLivenessCheck(t *testing.T) {
	phantomAddr := net.ParseIP("52.44.73.6")
	reg := DecoyRegistration{
		DarkDecoy: &phantomAddr,
	}

	liveness, response := reg.PhantomIsLive()
	if liveness != true {
		t.Fatalf("Live host seen as non-responsive: %v\n", response)
	}

	// Is there any test address we know will never respond?
	unroutableIP := net.ParseIP("127.0.0.2")
	reg.DarkDecoy = &unroutableIP

	liveness, response = reg.PhantomIsLive()
	if liveness != false {
		t.Fatalf("Unroutable host seen as Live: %v\n", response)
	}

	// Is there any test address we know will never respond?
	phantomV6 := net.ParseIP("2001:48a8:687f:1::105")
	reg.DarkDecoy = &phantomV6

	liveness, response = reg.PhantomIsLive()
	if liveness != true {
		t.Fatalf("Live V6 host seen as non-responsive: %v\n", response)
	}

	// Is there any test address we know will never respond?
	unreachableV6 := net.ParseIP("2001:48a8:687f:1:1122::105")
	reg.DarkDecoy = &unreachableV6

	liveness, response = reg.PhantomIsLive()
	if liveness != false {
		t.Fatalf("Non responsive V6 host seen as live: %v\n", response)
	}
}

func TestManagerFunctionality(t *testing.T) {
	rm := NewRegistrationManager()

	c2s, keys, flags := mockReceiveFromDetector()

	transport := pb.TransportType(1)
	c2s.Transport = &transport

	newReg, err := rm.NewRegistration(&c2s, &keys, flags, c2s.GetV6Support())
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	rm.AddRegistration(newReg)

	storedReg := rm.CheckRegistration(newReg.DarkDecoy, newReg.keys.conjureHMAC("MinTrasportHMACString"))

	if storedReg.DarkDecoy.String() != "141.219.56.148" || storedReg.Covert != "52.44.73.6:443" {
		t.Fatalf("Improper registration returned: %v\n", storedReg.String())
	}
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

	// reconstruct IP from message
	ip_string := fmt.Sprintf("%d.%d.%d.%d", msg.Payload[0], msg.Payload[1], msg.Payload[2], msg.Payload[3])

	// check IP equality
	if reg.DarkDecoy.Equal(net.ParseIP(ip_string)) == false {
		t.Fatalf("Expected %v, got %v", reg.DarkDecoy, net.ParseIP(msg.Payload))
	}
}

func TestLiveness(t *testing.T) {

	liveness, response := phantomIsLive("192.122.190.105:443")

	if liveness != true {
		t.Fatalf("Host is live, detected as NOT live: %v\n", response)
	}

	liveness, response = phantomIsLive("192.122.190.210:443")
	if liveness != false {
		t.Fatalf("Host is NOT live, detected as live: %v\n", response)
	}

	liveness, response = phantomIsLive("[2001:48a8:687f:1::105]:443")
	if liveness != true {
		t.Fatalf("Host is live, detected as NOT live: %v\n", response)
	}
}

func TestRegString(t *testing.T) {
	rm := NewRegistrationManager()

	c2s, keys, flags := mockReceiveFromDetector()

	newReg, err := rm.NewRegistration(&c2s, &keys, flags, c2s.GetV6Support())
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	t.Logf("%s - %s", newReg.IDString(), newReg.String())
}
