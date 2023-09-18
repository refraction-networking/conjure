package registration

import (
	dr "github.com/refraction-networking/conjure/pkg/registrars/decoy-registrar"
)

// NewDecoyRegistrar returns a decoy registrar..
func NewDecoyRegistrar() *dr.DecoyRegistrar {
	return dr.NewDecoyRegistrar()
}
