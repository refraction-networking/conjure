package interfaces

import (
	"io"

	pb "github.com/refraction-networking/gotapdance/protobuf"
)

// Overrides makes it possible to treat an array of overrides as a single override note that the
// subsequent overrides are not aware of those that come before so they may end up undoing their
// changes.
type Overrides []RegOverride

// Override implements the RegOverride interface.
func (o Overrides) Override(reg *pb.C2SWrapper, randReader io.Reader) error {
	var err error
	for _, override := range o {
		err = override.Override(reg, randReader)
		if err != nil {
			return err
		}
	}
	return nil
}

// RegOverride provides a generic way for the station to mutate an incoming registration before
// handing it off to the stations or returning it to the client as part of the RegResponse protobuf.
type RegOverride interface {
	Override(*pb.C2SWrapper, io.Reader) error
}
