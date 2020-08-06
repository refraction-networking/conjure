package min

import (
	"bytes"
	"net"

	dd "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/transports"
)

type Transport struct{}

func (Transport) Name() string      { return "MinTransport" }
func (Transport) LogPrefix() string { return "MIN" }

func (Transport) GetIdentifier(d *dd.DecoyRegistration) string {
	return string(d.Keys.ConjureHMAC("MinTrasportHMACString"))
}

func (Transport) WrapConnection(data *bytes.Buffer, c net.Conn, originalDst net.IP, regManager *dd.RegistrationManager) (*dd.DecoyRegistration, net.Conn, error) {
	if data.Len() < 32 {
		return nil, nil, transports.ErrTryAgain
	}

	hmacID := string(data.Bytes()[:32])
	reg, ok := regManager.GetRegistrations(originalDst)[hmacID]
	if !ok {
		return nil, nil, transports.ErrNotTransport
	}

	// We don't want the first 32 bytes
	data.Next(32)

	return reg, transports.PrependToConn(c, data), nil
}
