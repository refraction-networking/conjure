package webrtconjure

import (
	"bytes"
	"net"

	dd "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/transports"
)

const WebRTCIdentifierLen = 34

type Transport struct{}

func (Transport) Name() string      { return "WebRTCTransport" }
func (Transport) LogPrefix() string { return "WEBRTC" }

func (Transport) GetIdentifier(d *dd.DecoyRegistration) string {
	return string(r.Keys.SharedSecret) + string(r.Keys.DarkDecoySeed)
}

func (Transport) WrapConnection(data *bytes.Buffer, c net.Conn, phantom net.IP, regManager *dd.RegistrationManager) (*dd.DecoyRegistration, net.Conn, error) {
	if data.Len() < 32 {
		return nil, nil, transports.ErrTryAgain
	}

	hmacID := string(data.Bytes()[:32])
	reg, ok := regManager.GetRegistrations(phantom)[hmacID]
	if !ok {
		return nil, nil, transports.ErrNotTransport
	}

	// We don't want the first 32 bytes
	data.Next(32)

	return reg, transports.PrependToConn(c, data), nil
}

func getWebRTCRegistrations(regManager *dd.RegistrationManager, phantom net.IP) []*dd.DecoyRegistration {
	var regs []*dd.DecoyRegistration

	for identifier, r := range regManager.GetRegistrations(phantom) {
		if len(identifier) == WebRTCIdentifierLen { // Fix this Length check, or use other checking
			regs = append(regs, r)
		}
	}

	return regs
}
