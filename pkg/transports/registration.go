package transports

import (
	"net"

	"github.com/refraction-networking/obfs4/common/ntor"
)

type Registration interface {
	SharedSecret() []byte
	GetRegistrationAddress() string
	GetSrcPort() uint16
	PhantomIP() *net.IP
	PhantomPort() uint16
	Obfs4PublicKey() *ntor.PublicKey
	Obfs4NodeID() *ntor.NodeID
}

type RegManager interface {
	GetRegistrations(phantomAddr net.IP) map[string]Registration
}
