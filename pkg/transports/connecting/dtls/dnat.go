package dtls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"
)

func newDNAT() (*dnat, error) {
	const (
		IFF_TUN   = 0x0001
		IFF_NO_PI = 0x1000
		TUNSETIFF = 0x400454ca
	)

	tun, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var ifreq [0x28]byte

	coreCountStr := os.Getenv("CJ_CORECOUNT")
	coreCount, err := strconv.Atoi(coreCountStr)
	if err != nil {

		return nil, fmt.Errorf("error parsing core count: %v", err)
	}

	offsetStr := os.Getenv("OFFSET")
	offset, err := strconv.Atoi(offsetStr)
	if err != nil {
		return nil, fmt.Errorf("error parsing offset: %v", err)
	}

	copy(ifreq[:], "tun"+strconv.Itoa(offset+coreCount))

	flags := IFF_TUN | IFF_NO_PI
	binary.LittleEndian.PutUint16(ifreq[0x10:], uint16(flags))

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, tun.Fd(), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifreq[0])))
	if errno != 0 {
		tun.Close()
		return nil, errno
	}

	// Get the interface name
	name := string(ifreq[:bytes.IndexByte(ifreq[:], 0)])

	// Bring the interface up
	err = setUp(tun, name)
	if err != nil {
		return nil, fmt.Errorf("error bring the interface up: %v", err)
	}

	return &dnat{
		tun: tun,
	}, nil
}

// setUp brings up a network interface represented by the given name.
func setUp(tun *os.File, name string) error {
	ifreq, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("error creating ifreq: %v", err)
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return fmt.Errorf("error creating socket: %v", err)
	}

	// Get the current interface flags
	err = unix.IoctlIfreq(fd, syscall.SIOCGIFFLAGS, ifreq)
	if err != nil {
		return fmt.Errorf("error getting interface flags: %v", err)
	}

	ifreq.SetUint16(ifreq.Uint16() | syscall.IFF_UP)

	// Set the new interface flags
	err = unix.IoctlIfreq(fd, syscall.SIOCSIFFLAGS, ifreq)
	if err != nil {
		return fmt.Errorf("error setting interface flags: %v", err)
	}

	return nil
}

type dnat struct {
	tun *os.File
}

func (d *dnat) addEntry(src net.IP, sport uint16, dst *net.IP, dport uint16) error {
	ipLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    src,
		DstIP:    *dst,
		Protocol: layers.IPProtocolUDP,
	}

	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(sport),
		DstPort: layers.UDPPort(dport),
	}

	err := udpLayer.SetNetworkLayerForChecksum(ipLayer)
	if err != nil {
		return err
	}

	payload := []byte("Hello world")

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(buffer, opts,
		ipLayer,
		udpLayer,
		gopacket.Payload(payload),
	)
	if err != nil {
		return fmt.Errorf("error serializing injected packet: %v", err)
	}

	pkt := buffer.Bytes()
	_, err = d.tun.Write(pkt)
	if err != nil {
		return fmt.Errorf("error writing to tun interface: %v", err)
	}
	return nil
}
