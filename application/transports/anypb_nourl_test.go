package transports_test

import (
	"crypto/rand"
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

func TestMissingTypeURL(t *testing.T) {
	src, err := anypb.New(&pb.GenericTransportParams{RandomizeDstPort: proto.Bool(true)})
	require.Nil(t, err)
	src.TypeUrl = ""

	dst := &pb.GenericTransportParams{}
	err = anypb.UnmarshalTo(src, dst, proto.UnmarshalOptions{})
	require.NotNil(t, err)
}

func TestWrongType(t *testing.T) {
	src, err := anypb.New(&pb.ClientToStation{Padding: []byte{0, 1}})
	require.Nil(t, err)

	dst := &pb.GenericTransportParams{}
	err = transports.UnmarshalAnypbTo(src, dst)
	require.NotNil(t, err)
}

func TestGarbage(t *testing.T) {
	src, err := anypb.New(&pb.GenericTransportParams{RandomizeDstPort: proto.Bool(true)})
	require.Nil(t, err)
	garbagebytes, err := proto.Marshal(src)
	require.Nil(t, err)
	_, err = rand.Read(garbagebytes)
	require.Nil(t, err)

	dstAnypb := &anypb.Any{}

	err = proto.Unmarshal(garbagebytes, dstAnypb)
	require.NotNil(t, err)
}
