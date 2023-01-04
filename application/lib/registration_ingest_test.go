package lib

import (
	"encoding/hex"
	"net"
	"os"
	"testing"

	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/stretchr/testify/require"
)

func TestIngestPortHandling(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	rm := NewRegistrationManager(&RegConfig{})
	require.NotNil(t, rm)

	// The mock registration has transport id 0, so we hard code that here too
	var transportType pb.TransportType = 0
	err := rm.AddTransport(transportType, mockTransport{})
	require.Nil(t, err)

	c2s, keys := mockReceiveFromDetector()
	require.NotNil(t, keys)
	c2s.Transport = &transportType

	regSource := pb.RegistrationSource_Detector

	c2sw := &pb.C2SWrapper{
		RegistrationPayload: &c2s,
		RegistrationSource:  &regSource,
		RegistrationAddress: net.ParseIP("1.1.1.1"),
	}

	reg, err := rm.NewRegistrationC2SWrapper(c2sw, true)
	require.Nil(t, err)
	require.NotNil(t, reg)

	// No
	require.Equal(t, 443, int(reg.PhantomPort))
}

func TestIngestPortHandlingCases(t *testing.T) {
	fl := false
	tr := true

	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	rm := NewRegistrationManager(&RegConfig{})
	require.NotNil(t, rm)

	// The mock registration has transport id 0, so we hard code that here too
	var transportType pb.TransportType = 0
	err := rm.AddTransport(transportType, mockTransport{})
	require.Nil(t, err)

	goodCases := []struct {
		t        pb.TransportType
		p        *pb.GenericTransportParams
		expected uint16
	}{
		// registrations that provide no transport parameters should be allowed to be backward
		// compatible with clients before the addition of the transport parameters field.
		{t: transportType, p: nil, expected: 443},

		// Allow transports that support fixed destination port to disable randomization
		{t: transportType, p: &pb.GenericTransportParams{RandomizeDstPort: &fl}, expected: 443},

		// Allow transports that support randomized destination port to enable randomization through
		// transport parameter in the registration.
		{t: transportType, p: &pb.GenericTransportParams{RandomizeDstPort: &tr}, expected: 444},
	}
	seed, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")

	for _, testCase := range goodCases {
		port, err := rm.GetPhantomDstPort(testCase.t, testCase.p, seed, randomizeDstPortMinVersion)
		require.Nil(t, err)
		require.Equal(t, testCase.expected, port)
	}
}
