package transports

import (
	"net"

	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/obfs4/common/ntor"
)

type Registration interface {
	SharedSecret() []byte
	GetRegistrationAddress() string
	GetSrcPort() uint16
	PhantomIP() *net.IP
	PhantomPort() uint16
	Obfs4PublicKey() *ntor.PublicKey
	Obfs4PrivateKey() *ntor.PrivateKey
	Obfs4NodeID() *ntor.NodeID
	Transport() pb.TransportType
	TransportParams() any
}

type RegManager interface {
	GetRegistrations(phantomAddr net.IP) map[string]Registration
}
