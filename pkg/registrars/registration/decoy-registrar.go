package registration

import (
	dr "github.com/refraction-networking/conjure/pkg/registrars/decoy-registrar"
	tls "github.com/refraction-networking/utls"
)

// NewDecoyRegistrar returns a decoy registrar with default width and ClientHello ID.
func NewDecoyRegistrar() *dr.DecoyRegistrar {
	return dr.NewDecoyRegistrar()
}

// NewDecoyRegistrarWith returns a decoy registrar with custom width and ClientHello ID.
func NewDecoyRegistrarWith(width uint, chID tls.ClientHelloID) *dr.DecoyRegistrar {
	return dr.NewDecoyRegistrar()
}
