package oscur0

import (
	"fmt"
	"net"

	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/phantoms"
)

func Dial(raddr *net.UDPAddr, config Config) (*Conn, error) {
	keys, err := genkeys(config.PubKey)
	if err != nil {
		return nil, fmt.Errorf("error generating keys: %v", err)
	}

	return dial(raddr, config, keys)
}

func dial(raddr *net.UDPAddr, config Config, keys *core.SharedKeys) (*Conn, error) {

	pConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("error creating udp packet conn: %v", err)
	}

	return client(pConn, raddr, config, keys)
}

func DialPhantom(config Config) (*Conn, error) {
	keys, err := genkeys(config.PubKey)
	if err != nil {
		return nil, fmt.Errorf("error generating keys: %v", err)
	}

	phantom, err := phantoms.SelectPhantom(keys.ConjureSeed, phantoms.GetDefaultPhantomSubnets(), nil, true)
	if err != nil {
		return nil, fmt.Errorf("error selecting phantom: %v", err)
	}

	return dial(&net.UDPAddr{IP: *phantom.IP()}, config, keys)
}

func genkeys(pubkey []byte) (*core.SharedKeys, error) {

	pubkey32bytes, err := sliceToArray(pubkey)
	if err != nil {
		return nil, err
	}

	return core.GenerateClientSharedKeys(pubkey32bytes)
}
