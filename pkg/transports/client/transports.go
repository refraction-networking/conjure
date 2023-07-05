package transports

import (
	"errors"

	cj "github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/min"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/obfs4"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/prefix"
	pb "github.com/refraction-networking/conjure/proto"
)

var transportsByName map[string]cj.Transport = make(map[string]cj.Transport)
var transportsByID map[pb.TransportType]cj.Transport = make(map[pb.TransportType]cj.Transport)

var (
	// ErrAlreadyRegistered error when registering a transport that matches
	// an already registered ID or name.
	ErrAlreadyRegistered = errors.New("transport already registered")

	// ErrUnknownTransport provided id or name does npt match any enabled
	// transport.
	ErrUnknownTransport = errors.New("unknown transport")
)

// New returns a new Transport
func New(name string) (cj.Transport, error) {
	transport, ok := transportsByName[name]
	if !ok {
		return nil, ErrUnknownTransport
	}

	return transport, nil
}

// NewWithParams returns a new Transport and attempts to set the parameters provided
func NewWithParams(name string, params any) (cj.Transport, error) {
	transport, ok := transportsByName[name]
	if !ok {
		return nil, ErrUnknownTransport
	}

	err := transport.SetParams(params)
	return transport, err
}

// GetTransportByName returns transport by name
func GetTransportByName(name string) (cj.Transport, bool) {
	t, ok := transportsByName[name]
	return t, ok
}

// GetTransportByID returns transport by name
func GetTransportByID(id pb.TransportType) (cj.Transport, bool) {
	t, ok := transportsByID[id]
	return t, ok
}

var defaultTransports = []cj.Transport{
	&min.ClientTransport{},
	&obfs4.ClientTransport{},
	&prefix.ClientTransport{},
}

// AddTransport adds new transport
func AddTransport(t cj.Transport) error {
	name := t.Name()
	id := t.ID()

	if _, ok := transportsByName[name]; ok {
		return ErrAlreadyRegistered
	} else if _, ok := transportsByID[id]; ok {
		return ErrAlreadyRegistered
	}

	transportsByName[name] = t
	transportsByID[id] = t
	return nil
}

// EnableDefaultTransports initializes the library with default transports
func EnableDefaultTransports() error {
	var err error
	for _, t := range defaultTransports {
		err = AddTransport(t)
		if err != nil {
			return err
		}
	}

	return nil
}

func init() {
	err := EnableDefaultTransports()
	if err != nil {
		panic(err)
	}
}

func ConfigFromTransportType(transportType pb.TransportType, randomizePortDefault bool) (cj.Transport, error) {
	switch transportType {
	case pb.TransportType_Min:
		return &min.ClientTransport{Parameters: &pb.GenericTransportParams{RandomizeDstPort: &randomizePortDefault}}, nil
	case pb.TransportType_Obfs4:
		return &obfs4.ClientTransport{Parameters: &pb.GenericTransportParams{RandomizeDstPort: &randomizePortDefault}}, nil
	default:
		return nil, errors.New("unknown transport by TransportType try using TransportConfig")
	}
}
