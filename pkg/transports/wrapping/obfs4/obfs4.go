package obfs4

import (
	"bytes"
	"fmt"
	"net"

	cj "github.com/refraction-networking/conjure/pkg/station/lib"
	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	"gitlab.com/yawning/obfs4.git/common/drbg"
	"gitlab.com/yawning/obfs4.git/common/ntor"
	"gitlab.com/yawning/obfs4.git/transports/obfs4"
	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	// Earliest client library version ID that supports destination port randomization
	randomizeDstPortMinVersion uint = 3

	// port range boundaries for min when randomizing
	portRangeMin = 22
	portRangeMax = 65535
)

// Transport implements the station Transport interface for the obfs4 transport
type Transport struct{}

// Name implements the station Transport interface
func (Transport) Name() string { return "obfs4" }

// LogPrefix implements the station Transport interface
func (Transport) LogPrefix() string { return "OBFS4" }

// GetIdentifier implements the station Transport interface
func (Transport) GetIdentifier(r *cj.DecoyRegistration) string {
	return string(r.Keys.Obfs4Keys.PublicKey.Bytes()[:]) + string(r.Keys.Obfs4Keys.NodeID.Bytes()[:])
}

// GetProto returns the next layer protocol that the transport uses. Implements
// the Transport interface.
func (Transport) GetProto() pb.IPProto {
	return pb.IPProto_Tcp
}

// ParseParams gives the specific transport an option to parse a generic object
// into parameters provided by the client during registration.
func (Transport) ParseParams(libVersion uint, data *anypb.Any) (any, error) {
	if data == nil {
		return nil, nil
	}

	// For backwards compatibility we create a generic transport params object
	// for transports that existed before the transportParams fields existed.
	if libVersion < randomizeDstPortMinVersion {
		f := false
		return &pb.GenericTransportParams{
			RandomizeDstPort: &f,
		}, nil
	}

	var m = &pb.GenericTransportParams{}
	err := transports.UnmarshalAnypbTo(data, m)
	return m, err
}

// ParamStrings returns an array of tag string that will be added to tunStats when a proxy
// session is closed. For now, no params of interest.
func (t Transport) ParamStrings(p any) []string {
	return nil
}

// WrapConnection implements the station Transport interface
func (Transport) WrapConnection(data *bytes.Buffer, c net.Conn, phantom net.IP, regManager *cj.RegistrationManager) (*cj.DecoyRegistration, net.Conn, error) {
	if data.Len() < ClientMinHandshakeLength {
		return nil, nil, transports.ErrTryAgain
	}

	var representative ntor.Representative
	copy(representative[:ntor.RepresentativeLength], data.Bytes()[:ntor.RepresentativeLength])

	for _, r := range getObfs4Registrations(regManager, phantom) {
		mark := generateMark(r.Keys.Obfs4Keys.NodeID, r.Keys.Obfs4Keys.PublicKey, &representative)
		pos := findMarkMac(mark, data.Bytes(), ntor.RepresentativeLength+ClientMinPadLength, MaxHandshakeLength, true)
		if pos == -1 {
			continue
		}

		// We found the mark in the client handshake! We found our registration!
		args := pt.Args{}
		args.Add("node-id", r.Keys.Obfs4Keys.NodeID.Hex())
		args.Add("private-key", r.Keys.Obfs4Keys.PrivateKey.Hex())
		seed, err := drbg.NewSeed()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create DRBG seed: %w", err)
		}
		args.Add("drbg-seed", seed.Hex())

		t := &obfs4.Transport{}

		factory, err := t.ServerFactory("", &args)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create server factory: %w", err)
		}

		mc := transports.PrependToConn(c, data)
		wrapped, err := factory.WrapConn(mc)

		return r, wrapped, err
	}

	// If we read more than min handshake len, but less than max and didn't find
	// the mark get more bytes until we have reached the max handshake length.
	// If we have reached the max handshake len and didn't find it return NotTransport
	if data.Len() < MaxHandshakeLength {
		return nil, nil, transports.ErrTryAgain
	}

	// The only time we'll make it here is if there are no obfs4 registrations
	// for the given phantom.
	return nil, nil, transports.ErrNotTransport
}

// This function makes the assumption that any identifier with length 52 is an obfs4 registration.
// This may not be strictly true, but any other identifier will simply fail to form a connection and
// should be harmless.
func getObfs4Registrations(regManager *cj.RegistrationManager, darkDecoyAddr net.IP) []*cj.DecoyRegistration {
	var regs []*cj.DecoyRegistration

	for identifier, r := range regManager.GetRegistrations(darkDecoyAddr) {
		if len(identifier) == ntor.PublicKeyLength+ntor.NodeIDLength {
			regs = append(regs, r)
		}
	}

	return regs
}

// GetDstPort Given the library version, a seed, and a generic object
// containing parameters the transport should be able to return the
// destination port that a clients phantom connection will attempt to reach
func (Transport) GetDstPort(libVersion uint, seed []byte, params any) (uint16, error) {

	if libVersion < randomizeDstPortMinVersion {
		return 443, nil
	}

	if params == nil {
		return 443, nil
	}

	parameters, ok := params.(*pb.GenericTransportParams)
	if !ok {
		return 0, fmt.Errorf("bad parameters provided")
	}

	if parameters.GetRandomizeDstPort() {
		return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
	}

	return 443, nil
}
