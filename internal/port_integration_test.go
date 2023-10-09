package integration_test

import (
	"context"
	"crypto/rand"
	"os"
	"testing"

	"github.com/refraction-networking/conjure/internal/conjurepath"
	"github.com/refraction-networking/conjure/internal/testutils"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/station/log"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/ed25519"
	"github.com/refraction-networking/ed25519/extra25519"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestBase(T *testing.T) {
	T.Run("TestBase", func(T *testing.T) {
		require.Equal(T, 1, 1)
	})
}

func TestTransportPortSelection(t *testing.T) {
	if *debug {
		log.SetLevel(log.DebugLevel)
	}

	var testCases = getTestCases(t)
	for _, testCase := range testCases {
		t.Run(testCase.clientTransport.Name(), func(t *testing.T) {
			testTransportPortSelection(t, testCase.stationTransportBuilder, testCase.clientTransport, testCase.clientParamPermuteGenerator)
		})
	}
}

func testTransportPortSelection(t *testing.T, builder stationBuilder, clientTransport interfaces.WrappingTransport, clientParamPermuteGenerator func() []TestParams) {
	testSubnetPath := conjurepath.Root + "/pkg/station/lib/test/phantom_subnets.toml"
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)
	libver := uint(core.CurrentClientLibraryVersion())

	_, private, _ := ed25519.GenerateKey(rand.Reader)

	var curve25519Public, curve25519Private [32]byte
	extra25519.PrivateKeyToCurve25519(&curve25519Private, private)
	curve25519.ScalarBaseMult(&curve25519Public, &curve25519Private)

	transport := builder(curve25519Private)
	transportType := clientTransport.ID()

	// Ensure that we test all given parameter permutations as well as nil params
	paramSet := append([]TestParams{nil}, clientParamPermuteGenerator()...)

	for _, testParams := range paramSet {
		if testParams == nil {
			testParams = &nilParams{}
		}
		params := testParams.GetParams()
		clientKeys, err := core.GenerateClientSharedKeys(curve25519Public)
		require.Nil(t, err)

		err = clientTransport.SetParams(params)
		require.Nil(t, err)

		// ensure that if the registration w/ transport config is re-used then the selected port is
		// still consistent between the client and server.
		for i := 0; i < 10; i++ {
			gen := uint32(i%2 + 1) // the subnet set n gen1 doesn't support phantom randomization, the set in gen2 does

			err = clientTransport.Prepare(context.Background(), nil)
			require.Nil(t, err)

			protoParams, err := clientTransport.GetParams()
			require.Nil(t, err)
			log.Debugf("running %s w/ %s", clientTransport.Name(), testParams.String())

			manager := testutils.SetupRegistrationManager(testutils.Transport{Index: transportType, Transport: transport})
			require.NotNil(t, manager)

			v := uint32(libver)
			covert := "1.2.3.4:56789"
			regType := pb.RegistrationSource_API
			c2s := &pb.ClientToStation{
				ClientLibVersion:    &v,
				Transport:           &transportType,
				CovertAddress:       &covert,
				DecoyListGeneration: &gen,
			}
			if params != nil {
				p, err := anypb.New(protoParams)
				if err != nil {
					log.Fatalln("failed to make params", err)
				}
				c2s.TransportParams = p
			}

			keys, err := core.GenSharedKeys(libver, clientKeys.SharedSecret, transportType)
			if err != nil {
				log.Fatalln("failed to generate shared keys:", err)
			}

			for _, v6Reg := range []bool{false, true} {
				phantom, err := manager.PhantomSelector.Select(
					clientKeys.ConjureSeed, uint(gen), libver, v6Reg)
				require.Nil(t, err)

				reg, err := manager.NewRegistration(c2s, &keys, v6Reg, &regType)
				require.Nil(t, err, "failed to create new Registration")

				reg.Transport = transportType

				// Get the port that the client will connect to
				clientPort, err := clientTransport.GetDstPort(clientKeys.ConjureSeed)
				require.Nil(t, err, "failed to get client port")

				serverPort := reg.PhantomPort

				if phantom.SupportRandomPort() {
					// If the phantom supports random ports, then the client and server should pick
					// the same randomized destination port
					require.Equal(t, clientPort, serverPort, "c:%d != s:%d - %s %s", clientPort, serverPort, transport.Name(), testParams.String())
				} else {
					// If the phantom does not support random ports, then the server should pick 443
					// the client applies this policy at a higher level so we don't check it here.
					require.Equal(t, uint16(443), serverPort, "443 != s:%d - %s %s", serverPort, transport.Name(), testParams.String())
				}
			}
		}
	}
}
