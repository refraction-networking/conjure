package client

import (
	"testing"

	"github.com/refraction-networking/conjure/pkg/transports/wrapping/prefix"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestConjureTransportOverride(t *testing.T) {
	reg := ConjureReg{v6Support: V4 | V6}
	reg.ConjureSession = &ConjureSession{}
	reg.ConjureSession.DisableRegistrarOverrides = false
	reg.Transport = &prefix.ClientTransport{}

	err := reg.UnpackRegResp(nil)
	require.Nil(t, err)

	regResp := &pb.RegistrationResponse{}

	err = reg.UnpackRegResp(regResp)
	require.Nil(t, err)

	var id int32 = -2
	truePtr := true
	tp := &pb.PrefixTransportParams{
		PrefixId:         &id,
		Prefix:           []byte("aaaa"),
		RandomizeDstPort: &truePtr,
	}
	apb, _ := anypb.New(tp)
	regResp = &pb.RegistrationResponse{
		TransportParams: apb,
	}

	// Make sure that when overrides are allowed, they are applied even if it is not a prefix that
	// is included in the default prefixes that the client knows about.
	err = reg.UnpackRegResp(regResp)
	require.Nil(t, err)
	require.Equal(t, []byte("aaaa"), reg.Transport.(*prefix.ClientTransport).Prefix.Bytes())
	require.Equal(t, prefix.PrefixID(id), reg.Transport.(*prefix.ClientTransport).Prefix.ID())
}
