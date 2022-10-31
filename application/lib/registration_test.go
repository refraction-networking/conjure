package lib

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type mockTransport struct{}

func (mockTransport) Name() string      { return "MockTransport" }
func (mockTransport) LogPrefix() string { return "MOCK" }

func (mockTransport) GetIdentifier(d *DecoyRegistration) string {
	return string(d.Keys.ConjureHMAC("MockTrasportHMACString"))
}

func (mockTransport) WrapConnection(data *bytes.Buffer, c net.Conn, originalDst net.IP, regManager *RegistrationManager) (*DecoyRegistration, net.Conn, error) {
	return nil, nil, nil
}

func mockReceiveFromDetector() (pb.ClientToStation, ConjureSharedKeys) {
	clientToStationBytes, _ := hex.DecodeString("109a04180ba2010e35322e34342e37332e363a343433b00100a2060100")
	sharedSecret, _ := hex.DecodeString("5414c734ad5dc53e6b56a7bb47ce695a14a3ef076a3d5ace9cbf3b4d12706b73")

	clientToStation := &pb.ClientToStation{}
	err := proto.Unmarshal(clientToStationBytes, clientToStation)
	if err != nil {
		fmt.Printf("Failed to unmarshal ClientToStation protobuf\n")
	}

	var t bool = true
	var v uint32 = 1
	clientToStation.Flags = &pb.RegistrationFlags{Use_TIL: &t}
	clientToStation.ClientLibVersion = &v

	conjureKeys, _ := GenSharedKeys(sharedSecret, 0)

	var testGeneration uint32 = 957
	clientToStation.DecoyListGeneration = &testGeneration

	return *clientToStation, conjureKeys
}

// func testEqualRegistrations(reg1 *DecoyRegistration, reg2 *DecoyRegistration) bool {
// 	return true
// }

// // This is not actually working yet
// func TestCreateDecoyRegistration(t *testing.T) {
// 	rm := NewRegistrationManager(&RegConfig{})

// 	c2s, keys := mockReceiveFromDetector()

// 	regSource := pb.RegistrationSource_Detector

// 	newReg, err := rm.NewRegistration(&c2s, &keys, c2s.GetV6Support(), &regSource)
// 	if err != nil {
// 		t.Fatalf("Registration failed: %v", err)
// 	}

// 	expectedReg := DecoyRegistration{}

// 	if !testEqualRegistrations(newReg, &expectedReg) {
// 		t.Fatalf("Bad registration Created")
// 	}
// }

func TestRegistrationLookup(t *testing.T) {
	rm := NewRegistrationManager(&RegConfig{})

	// The mock registration has transport id 0, so we hard code that here too
	err := rm.AddTransport(0, mockTransport{})
	require.Nil(t, err)

	c2s, keys := mockReceiveFromDetector()

	regSource := pb.RegistrationSource_Detector

	newReg, err := rm.NewRegistration(&c2s, &keys, c2s.GetV6Support(), &regSource)
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}
	t.Log(newReg)

	if rm.RegistrationExists(newReg) {
		t.Fatalf("Registration exists, but shouldn't")
	}
	rm.AddRegistration(newReg)
	if !rm.RegistrationExists(newReg) {
		t.Fatalf("Registration should exist, but doesn't")
	}
}

func TestRegisterForDetectorOnce(t *testing.T) {
	if os.Getenv("TEST_REDIS") != "1" {
		t.Skip("Skipping redis related test w/out mock")
	}
	reg := DecoyRegistration{
		DarkDecoy:        net.ParseIP("1.2.3.4"),
		registrationAddr: net.ParseIP(""),
	}

	ctx := context.Background()
	client := getRedisClient()
	if client == nil {
		t.Fatalf("couldn't connect to redis\n")
	}
	pubsub := client.Subscribe(ctx, DETECTOR_REG_CHANNEL)

	// go channel that receives published messages
	channel := pubsub.Channel()

	// send message to redis pubsub, wait, then close subscriber & channel
	registerForDetector(&reg)

	time.AfterFunc(time.Second*1, func() {
		_ = pubsub.Close()
	})

	// check message
	msg := <-channel
	if msg == nil {
		t.Fatalf("no messages received\n")
	}

	// reconstruct IP from message
	parsed := pb.StationToDetector{}
	err := proto.Unmarshal([]byte(msg.Payload), &parsed)
	if err != nil {
		t.Fatalf("Failed to parse protobuf")
	}

	// reconstruct IP from message
	recvPhantom := net.ParseIP(parsed.GetPhantomIp())
	recvClient := net.ParseIP(parsed.GetClientIp())

	// check IP equality
	if reg.DarkDecoy.String() != recvPhantom.String() {
		t.Fatalf("Expected Phantom %v, got %v", reg.DarkDecoy, recvPhantom)
	}

	if reg.registrationAddr.String() != recvClient.String() {
		t.Fatalf("Expected Client %v, got %v", reg.registrationAddr, recvClient)
	}
}

func TestRegisterForDetectorArray(t *testing.T) {
	if os.Getenv("TEST_REDIS") != "1" {
		t.Skip("Skipping redis related test w/out mock")
	}
	var addrs = []string{}
	var clientAddr = "192.0.2.1"
	for i := 0; i < 100; i++ {
		addrs = append(addrs, fmt.Sprintf("1.2.3.%d", i))
		addrs = append(addrs, fmt.Sprintf("2001::dead:beef:%x", i))
	}

	ctx := context.Background()
	client := getRedisClient()
	if client == nil {
		t.Fatalf("couldn't connect to redis\n")
	}
	pubsub := client.Subscribe(ctx, DETECTOR_REG_CHANNEL)
	defer pubsub.Close()

	// go channel that receives published messages
	channel := pubsub.Channel()

	for _, addr := range addrs {
		reg := &DecoyRegistration{
			DarkDecoy:        net.ParseIP(addr),
			registrationAddr: net.ParseIP(clientAddr),
		}

		// send message to redis pubsub, wait, then close subscriber & channel
		registerForDetector(reg)

		// check message
		msg := <-channel
		if msg == nil {
			t.Fatalf("no messages received %s\n", addr)
		}

		// reconstruct IP from message
		parsed := pb.StationToDetector{}
		err := proto.Unmarshal([]byte(msg.Payload), &parsed)
		if err != nil {
			t.Fatalf("Failed to parse protobuf")
		}

		// reconstruct IP from message
		recvPhantom := net.ParseIP(parsed.GetPhantomIp())
		recvClient := net.ParseIP(parsed.GetClientIp())

		// check IP equality
		if reg.DarkDecoy.String() != recvPhantom.String() {
			t.Fatalf("Expected Phantom %v, got %v", reg.DarkDecoy, recvPhantom)
		}

		if reg.registrationAddr.String() != recvClient.String() {
			t.Fatalf("Expected Client %v, got %v", reg.registrationAddr, recvClient)
		}
	}
}

func TestRegisterForDetectorMultithread(t *testing.T) {
	if os.Getenv("TEST_REDIS") != "1" {
		t.Skip("Skipping redis related test w/out mock")
	}
	var addrs = []string{}
	var wg sync.WaitGroup
	var failed = false
	var regNum = 100
	var clientAddr = "192.0.2.1"
	for i := 0; i < regNum; i++ {
		addrs = append(addrs, fmt.Sprintf("1.2.3.%d", i))
		addrs = append(addrs, fmt.Sprintf("2001::dead:beef:%x", i))
	}

	ctx := context.Background()
	client := getRedisClient()
	if client == nil {
		t.Fatalf("couldn't connect to redis\n")
	}
	pubsub := client.Subscribe(ctx, DETECTOR_REG_CHANNEL)
	defer pubsub.Close()

	// go channel that receives published messages
	channel := pubsub.Channel()

	for _, addr := range addrs {
		wg.Add(1)
		reg := &DecoyRegistration{
			DarkDecoy:        net.ParseIP(addr),
			registrationAddr: net.ParseIP(clientAddr),
		}

		// send message to redis pubsub, wait, then close subscriber & channel
		go func() {
			registerForDetector(reg)
		}()
	}

	i := 0
	go func() {
		for msg := range channel {
			// reconstruct IP from message
			parsed := &pb.StationToDetector{}
			err := proto.Unmarshal([]byte(msg.Payload), parsed)
			if err != nil {
				failed = true
			}

			recvClient := net.ParseIP(parsed.GetClientIp())
			if recvClient.String() != clientAddr {
				failed = true
			}
			i++
			wg.Done()
		}
	}()

	wg.Wait()

	if i != 2*regNum {
		t.Fatalf("Did not receive enough messages")
	}

	if failed {
		t.Fatalf("Failed to parse an ip")
	}
}

func TestRegString(t *testing.T) {
	rm := NewRegistrationManager(&RegConfig{})

	c2s, keys := mockReceiveFromDetector()

	regSource := pb.RegistrationSource_Detector

	newReg, err := rm.NewRegistration(&c2s, &keys, c2s.GetV6Support(), &regSource)
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	t.Logf("%s - %s", newReg.IDString(), newReg.String())
}
