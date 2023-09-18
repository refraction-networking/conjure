package connection

import (
	"net"

	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/transports/connecting/dtls"
)

type IPLogger func(logger func(asn uint, cc, tp string)) func(*net.IP)

func (cm *connManager) BuildDTLSTransport(dtlsBuilder interfaces.DnatBuilder, logIPDTLS IPLogger) (*dtls.Transport, error) {
	return dtls.NewTransport(
		logIPDTLS(cm.AddAuthFailConnecting),
		logIPDTLS(cm.AddOtherFailConnecting),
		logIPDTLS(cm.AddCreatedToDialSuccessfulConnecting),
		logIPDTLS(cm.AddCreatedToListenSuccessfulConnecting),
		dtlsBuilder,
	)
}
