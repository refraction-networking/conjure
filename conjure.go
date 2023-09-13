package conjure

import (
	"github.com/refraction-networking/conjure/pkg/client/assets"
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	transports "github.com/refraction-networking/conjure/pkg/transports/client"
	pb "github.com/refraction-networking/conjure/proto"
)

type Assets assets.ClientInterface

func GetAssets() Assets {
	return assets.Assets()
}

func SetAssetsDir(dir string) (Assets, error) {
	return assets.AssetsSetDir(dir)
}

var (
	// ErrUnknownTransport provided id or name does npt match any enabled transport.
	ErrUnknownTransport = transports.ErrUnknownTransport
)

// Transport provides a generic interface for utilities that allow the client to dial and connect to
// a phantom address when creating a Conjure connection.
type Transport interfaces.Transport

// Registrar defines the interface for a module completing the initial portion of the conjure
// protocol which registers the clients intent to connect, along with the specifics of the session
// they wish to establish.
type Registrar interfaces.Registrar

// GetTransportByName returns transport by name
func GetTransportByName(name string) (interfaces.Transport, bool) {
	return transports.GetTransportByName(name)
}

// GetTransportByID returns transport by name
func GetTransportByID(id pb.TransportType) (interfaces.Transport, bool) {
	return transports.GetTransportByID(id)
}

// GetTransportWithParams returns a new Transport and attempts to set the parameters provided
func GetTransportWithParams(name string, params any) (interfaces.Transport, error) {
	return transports.NewWithParams(name, params)
}

// GetTransportWithParamsByID returns a new Transport by Type ID, if one exists, and attempts to set the
// parameters provided.
func GetTransportWithParamsByID(id pb.TransportType, params any) (interfaces.Transport, error) {
	return transports.NewWithParamsByID(id, params)
}
