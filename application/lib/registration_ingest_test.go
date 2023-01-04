package lib

import (
	"encoding/hex"
	"net"
	"os"
	"testing"

	"github.com/refraction-networking/conjure/application/log"

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

func TestIngestPortHandlingFunctionality(t *testing.T) {
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
		// registrations that provide no transport parameters should be allowed so we are backward
		// compatible with clients from before the addition of the transport parameters field.
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

func TestIngestPortHandlingCorners(t *testing.T) {
	fl := false
	tr := true

	os.Setenv("PHANTOM_SUBNET_LOCATION", "./test/phantom_subnets.toml")
	rm := NewRegistrationManager(&RegConfig{})
	require.NotNil(t, rm)

	rm.Logger.SetLevel(log.TraceLevel)

	// The mock registration has transport id 0, so we hard code that here too
	err := rm.AddTransport(mockID, mockTransport{})
	require.Nil(t, err)
	err = rm.AddTransport(mockIDRO, mtro{})
	require.Nil(t, err)
	err = rm.AddTransport(mockIDFO, mtfo{})
	require.Nil(t, err)

	cases := []struct {
		t   pb.TransportType
		p   *pb.GenericTransportParams
		v   uint
		err string
	}{
		// Registrations with unknown (not added to the registration manager) transport type return
		// an error indicating unknown transport.
		{t: -1, p: nil, v: randomizeDstPortMinVersion, err: "unknown transport"},
		{t: 50, p: &pb.GenericTransportParams{RandomizeDstPort: &fl}, v: randomizeDstPortMinVersion, err: "unknown transport"},

		// If randomization is enabled in transport params, but the client lib version
		{t: mockID, p: &pb.GenericTransportParams{RandomizeDstPort: &tr}, v: 0, err: "randomization requested in params by low client lib version"},

		// If a transport that does not support dst port randomization is selected, but
		// randomization is requested by parameter throw an error.
		{t: mockIDFO, p: &pb.GenericTransportParams{RandomizeDstPort: &tr}, v: randomizeDstPortMinVersion, err: "port randomization requested by param, but not supported by transport"},

		// If a transport that does not support static dst port is selected, but randomization is
		// disabled by parameter throw an error.
		{t: mockIDRO, p: nil, v: randomizeDstPortMinVersion, err: "fixed port requested by param, but not supported by selected transport"},
		{t: mockIDRO, p: &pb.GenericTransportParams{RandomizeDstPort: &fl}, v: randomizeDstPortMinVersion, err: "fixed port requested by param, but not supported by selected transport"},
	}
	seed, _ := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")

	for _, testCase := range cases {
		_, err := rm.GetPhantomDstPort(testCase.t, testCase.p, seed, testCase.v)
		require.NotNil(t, err, "case: %v", testCase)
		require.Equal(t, testCase.err, err.Error(), "case: %v", testCase)
	}
}
