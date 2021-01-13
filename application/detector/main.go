package main

import (
	"bytes"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
)

// Detector implements a single thread packet capture process forming a critical
// piece of a refraction networking station. This simple detector is independent
// of the Tapdance style registration components of the more heavyweight Rust
// detector implementation and is (at present) meant purely for testing and use
// with the API based registrars.
type Detector struct {
	// interface to listen on
	Iface string

	// List of addresses to filter packets from (i.e. liveness testing)
	FilterList []string

	// Check if a packet is registered based on the destination address
	IsRegistered func(addr string) bool

	// Tags checked for routing investigation purposes.
	Tags []string

	// Logger provided by initializing application.
	Logger *log.Logger

	// TODO
	// Stats tracking to mimic rust station
	stats int
}

// Run sets the detector running, capturing traffic and processing checking for
// connections associated with registrations.
func (det *Detector) Run() {

	if !deviceExists(det.Iface) {
		log.Fatal("Unable to open device ", iface)
	}

	// Open packet reader in promiscuous mode.
	handler, err := pcap.OpenLive(det.Iface, buffer, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()

	//Generate and Apply filters
	filter := generateFilters(det.FilterList)
	if err := handler.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	// Actually process packets
	source := gopacket.NewPacketSource(handler, handler.LinkType())
	for packet := range source.Packets() {
		det.handlePacket(packet)
	}

	det.Logger.Printf("Detector Shutting Down\n")
}

func (det *Detector) handlePacket(packet gopacket.Packet) {

	det.checkForTags(packet)

	dst := packet.NetworkLayer().NetworkFlow().Dst()
	if det.IsRegistered(dst.String()) {
		det.forwardPacket(packet)
	}
}

// Current stations check packets for tags (UDP specifically to check DNS)
// TODO
func (det *Detector) checkForTags(packet gopacket.Packet) {
	for _, tag := range det.Tags {
		if bytes.Contains(packet.ApplicationLayer().Payload(), []byte(tag)) {
			dst := packet.NetworkLayer().NetworkFlow().Dst()
			src := packet.NetworkLayer().NetworkFlow().Src()
			det.Logger.Println(src, "->", dst)
		}
	}
}

// Connect tot the tun interface and send the packet to the other portion of
// the refraction station. TODO
func (det *Detector) forwardPacket(packet gopacket.Packet) {
	dst := packet.NetworkLayer().NetworkFlow().Dst()
	src := packet.NetworkLayer().NetworkFlow().Src()
	det.Logger.Println(src, "->", dst)
}

func generateFilters(filterList []string) string {

	if len(filterList) == 0 {
		return ""
	}

	out := "tcp and not src " + filterList[0]
	for _, entry := range filterList[1:] {
		out += " and not src " + entry
	}

	return out
}

func deviceExists(name string) bool {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panic(err)
	}

	for _, device := range devices {
		if device.Name == name {
			return true
		}
	}
	return false
}

var (
	iface  = "wlp4s0"
	buffer = int32(1600)
	filter = "tcp and port 22 and not src 192.168.1.104"
)

func main() {

	det := &Detector{
		Iface:      iface,
		FilterList: []string{"192.168.1.104"},
		IsRegistered: func(addr string) bool {
			return true
		},
		Logger: logrus.New(),
	}

	det.Run()
}
