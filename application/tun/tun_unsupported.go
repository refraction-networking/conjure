// +build !linux

package tun

import (
	"fmt"
	"net"
	"os"
	"runtime"
)

func createInterface(flags uint16) (string, *os.File, error) {
	return "", nil, fmt.Errorf("%s is unsupported", runtime.GOOS)
}

func destroyInterface(name string) error {
	return fmt.Errorf("%s is unsupported", runtime.GOOS)
}

func openTun(_ string) (string, *os.File, error) {
	return createInterface(0)
}

func (t *Tun) setMTU(mtu int32) error {
	return nil
}

func (t *Tun) setIPv4(addr4 string) error {
	return nil
}

func (t *Tun) setIPv6(addr6 string) error {
	return nil
}

func (t *Tun) setOwner(owner uint32) error {
	return nil
}

func (t *Tun) setGroup(group uint32) error {
	return nil
}

func (t *Tun) setUp(iface *net.Interface) error {
	return nil
}
