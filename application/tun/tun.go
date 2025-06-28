// Package taptun provides an interface to the user level network
// TUN device.
//
// https://www.kernel.org/doc/Documentation/networking/tuntap.txt
package tun

import (
	"fmt"
	"net"
	"os"
)

// Tun represents a TUN Virtual Point-to-Point network device.
// implements io.ReadWriteCloser
type Tun struct {
	file  *os.File
	name  string
	iface *net.Interface
	sock4 int
	sock6 int
}

// NewTun creates a *Tun device with the specified name and returns the
// device connected to the tun interface.
//
// If an empty string ("") is specified for name, a tunN interface is
// created.
func NewTun(name string) (*Tun, error) {
	t, err := openTun(name)
	if err != nil {
		return nil, err
	}

	fmt.Println("1")

	// by default set owner to root
	err = t.setOwner(0)
	if err != nil {
		return t, err
	}
	fmt.Println("2")

	// by default set group to root
	err = t.setGroup(0)
	if err != nil {
		return t, err
	}
	fmt.Println("3")

	// err = setMTU(t, mtu)
	// if err != nil {
	// 	return nil, err
	// }

	return t, nil
}

func (t *Tun) Read(p []byte) (n int, err error) {
	return t.file.Read(p)
}

func (t *Tun) Write(p []byte) (n int, err error) {
	return t.file.Write(p)
}

// Close deallocate and remove the interface
func (t *Tun) Close() error {
	if err := t.file.Close(); err != nil {
		return err
	}
	return destroyInterface(t.name)
}

// OpenTun creates a tunN interface and returns a *Tun device connected to
// the tun interface.
func OpenTun() (*Tun, error) {
	return NewTun("")
}

// String return the name of the interface
func (t *Tun) String() string {
	return t.name
}

// SetMTU Set the Maximum transmission unit for the interface.
func (t *Tun) SetMTU(mtu int32) error {
	return t.setMTU(mtu)
}

// SetIPv6 Set the IPv4 address for the tun interface
func (t *Tun) SetIPv4(addr4 string) error {
	return t.setIPv4(addr4)
}

// SetIPv6 Set the IPv6 address for the tun interface
func (t *Tun) SetIPv6(addr6 string) error {
	return t.setIPv6(addr6)
}

// SetOwner Set the owner permission of the tun interface
func (t *Tun) SetOwner(owner uint32) error {
	return t.setOwner(owner)
}

// SetGroup Set the group permission of the tun interface
func (t *Tun) SetGroup(group uint32) error {
	return t.setGroup(group)
}

// SetUp Bring the interface "up"
func (t *Tun) SetUp() error {
	return t.setUp()
}
