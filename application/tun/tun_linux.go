package tun

/*
#cgo LDFLAGS:

#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"errors"
	"net"
	"os"
	"syscall"
	"unsafe"

	"fmt"

	"golang.org/x/sys/unix"
)

const (
	tunCloneDevice = "/dev/net/tun"
)

type interfaceRequest32 struct {
	name  [unix.IFNAMSIZ]byte
	flags int32
}

type interfaceRequest16 struct {
	name  [syscall.IFNAMSIZ]byte // c string
	flags uint16                 // c short
}

func openTun(name string) (*Tun, error) {
	return createInterface(syscall.IFF_TUN|syscall.IFF_NO_PI, name)
}

// func openTap(name string) (string, *os.File, error) {
// 	return createInterface(syscall.IFF_TAP|syscall.IFF_NO_PI, name)
// }

func createInterface(flags uint16, ifName string) (*Tun, error) {

	if len(ifName) > syscall.IFNAMSIZ-1 {
		return nil, errors.New("device name too long")
	}

	tunFlags := interfaceRequest16{
		name:  [syscall.IFNAMSIZ]byte{},
		flags: flags,
	}
	copy(tunFlags.name[:], []byte(ifName))

	// Create the tun interface. Use unix open so we can mark as non-blocking
	// before creating the file associated with the file descriptor.
	fd, err := unix.Open(tunCloneDevice, unix.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	// unix.SetNonblock(fd, true)
	f := os.NewFile(uintptr(fd), ifName)

	// copy([:len(tunFlags.name)-1], []byte(name+"\000"))

	err = ioctl(f.Fd(), syscall.TUNSETIFF, unsafe.Pointer(&tunFlags))
	if err != nil {
		return nil, err
	}

	// Create Socket file descriptors
	sock4, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return nil, err
	}

	sock6, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}

	// Create the golang net.Interface
	iface, err := net.InterfaceByName(ifName)

	return &Tun{
		file:  f,
		name:  ifName,
		iface: iface,
		sock4: sock4,
		sock6: sock6,
	}, err
}

func (t *Tun) setMTU(mtu int32) error {
	tunFlags := interfaceRequest32{
		name:  [unix.IFNAMSIZ]byte{},
		flags: int32(mtu),
	}
	copy(tunFlags.name[:], []byte(t.name))

	return ioctl(uintptr(t.sock4), unix.SIOCSIFMTU, unsafe.Pointer(&tunFlags))
}

func (t *Tun) setOwner(owner uint32) error {
	owner64 := uint64(owner)
	return ioctl(uintptr(t.file.Fd()), unix.TUNSETOWNER, unsafe.Pointer(&owner64))
}

func (t *Tun) setGroup(group uint32) error {
	group64 := uint64(group)
	return ioctl(uintptr(t.file.Fd()), unix.TUNSETGROUP, unsafe.Pointer(&group64))
}

func (t *Tun) setUp() error {
	ifr_up := interfaceRequest32{
		name:  [unix.IFNAMSIZ]byte{},
		flags: 0,
	}
	copy(ifr_up.name[:], []byte(t.name))

	err := ioctl(uintptr(t.sock4), unix.SIOCGIFFLAGS, unsafe.Pointer(&ifr_up))
	if err != nil {
		return err
	}

	ifr_up.flags = unix.IFF_UP | unix.IFF_RUNNING

	return ioctl(uintptr(t.sock4), unix.SIOCGIFFLAGS, unsafe.Pointer(&ifr_up))
}

type interfaceRequestSockaddrIn struct {
	name     [unix.IFNAMSIZ]byte
	sockaddr C.struct_sockaddr_in
}

func (t *Tun) setIPv4(addr4 string) error {
	ifr_ipaddr := interfaceRequestSockaddrIn{
		name: [unix.IFNAMSIZ]byte{},
	}

	copy(ifr_ipaddr.name[:], []byte(t.name))

	ifr_ipaddr.sockaddr.sin_family = syscall.AF_INET
	ip := C.CString(addr4)
	res := C.inet_pton(syscall.AF_INET, ip, unsafe.Pointer(&ifr_ipaddr.sockaddr.sin_addr))
	if res == 1 {
		return fmt.Errorf("error in v4 inet_pton parsing")
	}

	return ioctl(uintptr(t.sock4), unix.SIOCSIFADDR, unsafe.Pointer(&ifr_ipaddr))
}

type interfaceRequestIn6 struct {
	addr      C.struct_in6_addr
	prefixlen uint32
	ifindex   int32
}

func (t *Tun) setIPv6(addr6 string) error {
	ifr := interfaceRequest32{
		name:  [unix.IFNAMSIZ]byte{},
		flags: 0,
	}
	copy(ifr.name[:], []byte(t.name))

	err := ioctl(uintptr(t.sock6), syscall.SIOCGIFINDEX, unsafe.Pointer(&ifr))
	if err != nil {
		return err
	}

	ifr6 := interfaceRequestIn6{
		addr:      C.struct_in6_addr{},
		prefixlen: 64,
		ifindex:   ifr.flags,
	}
	ip := C.CString(addr6)
	res := C.inet_pton(syscall.AF_INET, ip, unsafe.Pointer(&ifr6.addr))
	if res == 1 {
		return fmt.Errorf("error in v6 inet_pton parsing")
	}

	return ioctl(uintptr(t.sock6), unix.SIOCSIFADDR, unsafe.Pointer(&ifr6))
}

func ioctl(fd, request uintptr, argp unsafe.Pointer) error {
	if _, _, e := syscall.Syscall6(syscall.SYS_IOCTL, fd, request, uintptr(argp), 0, 0, 0); e != 0 {
		return e
	}
	return nil
}

func destroyInterface(name string) error {
	//TODO
	return nil
}
