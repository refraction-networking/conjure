package transports

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
)

// UnmarshalAnypbTo unmarshals the src anypb to dst without reading the src type url.
// Used to unmarshal TransportParams in the registration message for saving space from
// the type url so that the registration payload is small enough for the DNS registrar.
func UnmarshalAnypbTo(src *anypb.Any, dst protoreflect.ProtoMessage) error {
	expected, err := anypb.New(dst)
	if err != nil {
		return fmt.Errorf("error reading src type: %v", err)
	}

	src.TypeUrl = expected.TypeUrl
	return anypb.UnmarshalTo(src, dst, proto.UnmarshalOptions{})
}
