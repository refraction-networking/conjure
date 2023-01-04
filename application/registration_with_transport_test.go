package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	cj "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/transports/wrapping/min"
	"github.com/refraction-networking/conjure/application/transports/wrapping/obfs4"

	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func mockReceiveFromDetector() (*pb.ClientToStation, cj.ConjureSharedKeys) {
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

	conjureKeys, _ := cj.GenSharedKeys(sharedSecret, 0)

	return clientToStation, conjureKeys
}

func TestManagerFunctionality(t *testing.T) {
	testSubnetPath := os.Getenv("GOPATH") + "/src/github.com/refraction-networking/conjure/application/lib/test/phantom_subnets.toml"
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	rm := cj.NewRegistrationManager(&cj.RegConfig{})

	c2s, keys := mockReceiveFromDetector()

	transport := pb.TransportType_Min
	gen := uint32(1)
	err := rm.AddTransport(pb.TransportType_Min, min.Transport{})
	require.Nil(t, err)
	c2s.Transport = &transport
	c2s.DecoyListGeneration = &gen

	source := pb.RegistrationSource_Detector
	newReg, err := rm.NewRegistration(c2s, &keys, c2s.GetV6Support(), &source)
	require.Nil(t, err, "registration failed")

	rm.AddRegistration(newReg)
	require.True(t, rm.RegistrationExists(newReg))

	potentialRegistrations := rm.GetRegistrations(newReg.PhantomIp)
	require.NotEqual(t, 0, len(potentialRegistrations))
	storedReg := potentialRegistrations[string(newReg.Keys.ConjureHMAC("MinTransportHMACString"))]
	require.NotNil(t, storedReg)

	if storedReg.PhantomIp.String() != "192.122.190.148" || storedReg.Covert != "52.44.73.6:443" {
		t.Fatalf("Improper registration returned: %v\n", storedReg.String())
	}
}

func TestPortSelectionInterfaces(t *testing.T) {
	var minT = min.Transport{}
	var obfs4T = obfs4.Transport{}
	var randDstPort cj.PortRandomizingTransport
	var fixedDstPort cj.FixedPortTransport

	// Ensure that the Fixed port interface for the existing transports (as of implementing port
	// randomization) return the backwards compatible fixed port (443)
	fixedDstPort = minT
	require.NotNil(t, fixedDstPort)
	require.Equal(t, uint16(443), fixedDstPort.ServicePort())

	fixedDstPort = obfs4T
	require.NotNil(t, fixedDstPort)
	require.Equal(t, uint16(443), fixedDstPort.ServicePort())

	// Ensure that the existing transport that implement Port randomization can be used as such.
	randDstPort = minT
	require.NotNil(t, randDstPort)
	selector := randDstPort.GetPortSelector()
	require.NotNil(t, selector)
	_, err := selector([]byte{}, nil)
	require.Nil(t, err)

	randDstPort = obfs4T
	require.NotNil(t, randDstPort)
	selector = randDstPort.GetPortSelector()
	require.NotNil(t, selector)
	_, err = selector([]byte{}, nil)
	require.Nil(t, err)

}
