package transports

import (
	// "net/pipe"
	"testing"

	cj "github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/min"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/stretchr/testify/require"
)

func TestTransportParameterFunctionality(t *testing.T) {
	tr := true
	fl := false
	paramsRandomize := &pb.GenericTransportParams{
		RandomizeDstPort: &tr,
	}
	paramsStatic := &pb.GenericTransportParams{
		RandomizeDstPort: &fl,
	}

	transport := &min.ClientTransport{}

	// If params is unset it returns nil
	params, err := transport.GetParams()
	require.Nil(t, err)
	require.Nil(t, params)

	transport.Parameters = paramsRandomize

	// Once params are set it returns a protobuf message that can be cast and parsed or otherwise
	// operated upon
	params, err = transport.GetParams()
	require.Nil(t, err)
	require.Equal(t, true, params.(*pb.GenericTransportParams).GetRandomizeDstPort())

	// We can then set the parameters if the proper parameters structure is provided even using
	// the generic transport interface.
	var gt cj.Transport = transport
	err = gt.SetParams(paramsStatic)
	require.Nil(t, err)

	// The updated parameters are reflected when we get the parameters,  again returning a protobuf
	// message that can be cast and parsed or otherwise operated upon.
	params, err = transport.GetParams()
	require.Nil(t, err)
	require.Equal(t, false, params.(*pb.GenericTransportParams).GetRandomizeDstPort())

	// if an improper object (any) is provided the cast in min will fail and SetParams will return
	// an error.
	badParams := struct{}{}
	err = gt.SetParams(badParams)
	require.EqualError(t, err, "unable to parse params")
}
