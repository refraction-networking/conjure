package main

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	dd "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/transports/wrapping/min"
	pb "github.com/refraction-networking/gotapdance/protobuf"
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
	rm := dd.NewRegistrationManager()

	c2s, keys := mockReceiveFromDetector()

	transport := pb.TransportType_Min
	rm.AddTransport(pb.TransportType_Min, min.Transport{})
	c2s.Transport = &transport

	newReg, err := rm.NewRegistration(c2s, &keys, c2s.GetV6Support())
	if err != nil {
		t.Fatalf("Registration failed: %v", err)
	}

	rm.AddRegistration(newReg)

	storedReg := rm.GetRegistrations(newReg.DarkDecoy)[string(newReg.Keys.ConjureHMAC("MinTrasportHMACString"))]

	if storedReg.DarkDecoy.String() != "141.219.56.148" || storedReg.Covert != "52.44.73.6:443" {
		t.Fatalf("Improper registration returned: %v\n", storedReg.String())
	}
}
