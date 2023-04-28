package transports_test

import (
	"math/rand"
	"testing"
	"unsafe"

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
	require.Nil(t, err)

	require.False(t, dst.GetRandomizeDstPort())
}

func TestGarbage(t *testing.T) {
	src, err := anypb.New(&pb.ClientToStation{Padding: []byte{0, 1}})
	require.Nil(t, err)
	ptr := unsafe.Pointer(src)

	for i := 0; i < int(unsafe.Sizeof(*src)); i++ {
		*(*int)(ptr) = rand.Int()
	}

	dst := &pb.GenericTransportParams{}
	err = transports.UnmarshalAnypbTo(src, dst)
	require.Nil(t, err)

	require.False(t, dst.GetRandomizeDstPort())
}
