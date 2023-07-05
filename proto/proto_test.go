package cjproto

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// Write a small go test using your APIMessage (serialize/deserialize)
func TestBidirectionalAPIResponse(t *testing.T) {
	c2s := RegistrationResponse{}
	addr := uint32(12345)
	c2s.Ipv4Addr = &addr
	port := uint32(10)
	c2s.DstPort = &port

	// Serialize
	marsh, err := proto.Marshal(&c2s)
	require.Nil(t, err)

	// Deserialize
	deser := RegistrationResponse{}
	err = proto.Unmarshal(marsh, &deser)
	require.Nil(t, err)
	require.Equal(t, addr, deser.GetIpv4Addr())
	require.Equal(t, port, deser.GetDstPort())
}

// TestProtoLibVer validates that the accessor method returns a default value for
// fields that are unset in a protobuf and that our initial incremented
// ClientLibraryVersion should be 1.
func TestProtoLibVer(t *testing.T) {
	c2s := ClientToStation{}

	defaultLibVer := c2s.GetClientLibVersion()
	require.Equal(t, uint32(0), defaultLibVer)
}
