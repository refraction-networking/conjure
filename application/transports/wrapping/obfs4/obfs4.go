package obfs4

import (
	"bytes"
	"fmt"
	"net"
	"os"

	pt "git.torproject.org/pluggable-transports/goptlib.git"
	dd "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/transports"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"gitlab.com/yawning/obfs4.git/common/drbg"
	"gitlab.com/yawning/obfs4.git/common/ntor"
	"gitlab.com/yawning/obfs4.git/transports/obfs4"
)

type Transport struct{}

func (Transport) Name() string      { return "obfs4" }
func (Transport) LogPrefix() string { return "OBFS4" }

func (Transport) GetIdentifier(r *dd.DecoyRegistration) string {
	return string(r.Keys.Obfs4Keys.PublicKey.Bytes()[:]) + string(r.Keys.Obfs4Keys.NodeID.Bytes()[:])
}

// GetProto returns the next layer protocol that the transport uses. Implements
// the Transport interface.
func (Transport) GetProto() pb.IpProto {
	return pb.IpProto_Tcp
}

func (Transport) WrapConnection(data *bytes.Buffer, c net.Conn, phantom net.IP, regManager *dd.RegistrationManager) (*dd.DecoyRegistration, net.Conn, error) {
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
		stateDir, err := os.MkdirTemp("", "")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create tmp-dir for WrapConn")
		}

		factory, err := t.ServerFactory(stateDir, &args)
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
func getObfs4Registrations(regManager *dd.RegistrationManager, darkDecoyAddr net.IP) []*dd.DecoyRegistration {
	var regs []*dd.DecoyRegistration

	for identifier, r := range regManager.GetRegistrations(darkDecoyAddr) {
		if len(identifier) == ntor.PublicKeyLength+ntor.NodeIDLength {
			regs = append(regs, r)
		}
	}

	return regs
}

// ServicePort returns the fixed port that the transport uses. Implements the
// FixedPortTransport interface for transports.
func (Transport) ServicePort() uint16 {
	return 443
}

const (
	portRangeMin = 22
	portRangeMax = 65535
)

// GetPortSelector returns a port selector created for this specific type of
// Transport.
func (Transport) GetPortSelector() func([]byte, any) (uint16, error) {
	return transports.PortSelectorRange(portRangeMin, portRangeMax)
}
