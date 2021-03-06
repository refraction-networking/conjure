package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/golang/protobuf/proto"
	dd "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/transports/wrapping/min"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/stretchr/testify/require"
)

func mockReceiveFromDetector() (*pb.ClientToStation, dd.ConjureSharedKeys) {
	clientToStationBytes, err := hex.DecodeString("109a04180ba2010e35322e34342e37332e363a343433b00100a2060100")
	sharedSecret, err := hex.DecodeString("5414c734ad5dc53e6b56a7bb47ce695a14a3ef076a3d5ace9cbf3b4d12706b73")

	clientToStation := &pb.ClientToStation{}
	err = proto.Unmarshal(clientToStationBytes, clientToStation)
	if err != nil {
		fmt.Printf("Failed to unmarshal ClientToStation protobuf\n")
	}

	t := true
	clientToStation.Flags = &pb.RegistrationFlags{Use_TIL: &t}

	conjureKeys, err := dd.GenSharedKeys(sharedSecret)

	return clientToStation, conjureKeys
}

func TestManagerFunctionality(t *testing.T) {
	testSubnetPath := os.Getenv("GOPATH") + "/src/github.com/refraction-networking/conjure/application/lib/test/phantom_subnets.toml"
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	rm := dd.NewRegistrationManager()

	c2s, keys := mockReceiveFromDetector()

	transport := pb.TransportType_Min
	gen := uint32(1)
	err := rm.AddTransport(pb.TransportType_Min, min.Transport{})
	require.Nil(t, err)
	c2s.Transport = &transport
	c2s.DecoyListGeneration = &gen

	source := pb.RegistrationSource_Detector
	newReg, err := rm.NewRegistration(c2s, &keys, c2s.GetV6Support(), &source)
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	rm.AddRegistration(newReg)

	storedReg := rm.GetRegistrations(newReg.DarkDecoy)[string(newReg.Keys.ConjureHMAC("MinTrasportHMACString"))]

	if storedReg.DarkDecoy.String() != "192.122.190.148" || storedReg.Covert != "52.44.73.6:443" {
		t.Fatalf("Improper registration returned: %v\n", storedReg.String())
	}
}
