package transports_test

import (
	"testing"

	"github.com/refraction-networking/conjure/application/transports"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestUnmarshall(t *testing.T) {
	src, err := anypb.New(&pb.GenericTransportParams{RandomizeDstPort: proto.Bool(true)})
	require.Nil(t, err)
	src.TypeUrl = ""

	dst := &pb.GenericTransportParams{}
	err = transports.UnmarshalAnypbTo(src, dst)
	require.Nil(t, err)

	require.True(t, dst.GetRandomizeDstPort())
}
