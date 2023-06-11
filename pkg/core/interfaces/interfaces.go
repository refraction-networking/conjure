package interfaces

import (
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

// Overrides makes it possible to treat an array of overrides as a single override note that the
// subsequent overrides are not aware of those that come before so they may end up undoing their
// changes.
type Overrides []RegOverride

// Override implements the RegOverride interface.
func (o Overrides) Override(r *pb.ClientToStation) (*pb.ClientToStation, error) {
	var err error
	for _, override := range o {
		r, err = override.Override(r)
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

// RegOverride provides a generic way for the station to mutate an incoming registration before
// handing it off to the stations or returning it to the client as part of the RegResponse protobuf.
type RegOverride interface {
	Override(r *pb.ClientToStation) (*pb.ClientToStation, error)
}
