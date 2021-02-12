package main

import (
	"bytes"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

	pb "github.com/refraction-networking/gotapdance/protobuf"
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

	// Tags checked for routing investigation purposes.
	Tags []string

	// Logger provided by initializing application.
	Logger *log.Logger

	// bool for independent thread to synchronize exit.
	exit bool

	// How often to log
	StatsFrequency int

	// TODO
	// Stats tracking to mimic rust detector
	stats *DetectorStats

	// TODO
	// State Tracking to allow for quick map lookup and timeout tracking.
	// - We could store one tracker per thread (which would prevent them from
	// 		contending but would require N times as much storage - 1 per thread)
	// - OR we could store one and have all access it via mutex. which might
	// 		slow access times and stuff, but minimizes storage requirements.
	tracker Tracker

	// Check storage for tracked entries past timeouts
	GarbageCollect func() error
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

	go det.StatsThread()

	// Actually process packets
	source := gopacket.NewPacketSource(handler, handler.LinkType())

	// To multithread source is actually a channel that you could pass to
	// workers. The workers would just then need to read `packet. ok` out of
	// the channel.
	// https://www.reddit.com/r/golang/comments/4ec2gu/hung_up_on_gopacket/
	for packet := range source.Packets() {
		det.handlePacket(packet)
	}

	det.exit = true
	det.Logger.Printf("Detector Shutting Down\n")
}

func (det *Detector) StatsThread() {
	for {
		det.Logger.Printf("stats %s", det.stats.Report())
		det.stats.Reset()

		if det.exit {
			return
		}
		time.Sleep(time.Duration(det.StatsFrequency) * time.Second)
	}
}

func (det *Detector) handlePacket(packet gopacket.Packet) {
	dst := packet.NetworkLayer().NetworkFlow().Dst()
	src := packet.NetworkLayer().NetworkFlow().Src()
	var dstPort uint16
	var packetLen = uint64(packet.Metadata().CaptureLength)
	det.stats.BytesTotal += packetLen

	switch len(dst.Raw()) {
	case 4:
		det.stats.V4PacketCount++
		det.stats.BytesV4 += packetLen
	case 16:
		det.stats.V6PacketCount++
		det.stats.BytesV6 += packetLen
	default:
		det.Logger.Warn("IP is not valid as IPv4 or IPv6")
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		dstPort = uint16(tcp.DstPort)
		det.checkForTags(packet)
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		dstPort = uint16(udp.DstPort)
		det.checkForTags(packet)
	} else {
		// Not handling protocols other than TCP and UDP right now.
		return
	}

	if det.tracker.IsRegistered(dst.String(), src.String(), dstPort) {
		det.stats.PacketsForwarded++
		det.forwardPacket(packet)
		det.tracker.Update(SessionExtension)
	}
}

// Current stations check packets for tags (UDP specifically to check DNS)
// TODO
func (det *Detector) checkForTags(packet gopacket.Packet) {
	for _, tag := range det.Tags {
		if bytes.Contains(packet.ApplicationLayer().Payload(), []byte(tag)) {
			dst := packet.NetworkLayer().NetworkFlow().Dst()
			src := packet.NetworkLayer().NetworkFlow().Src()
			det.Logger.Println("confirmed", src, "->", dst)
		}
	}
}

// Connect to the tun interface and send the packet to the other portion of
// the refraction station. TODO
func (det *Detector) forwardPacket(packet gopacket.Packet) {
	dst := packet.NetworkLayer().NetworkFlow().Dst()
	src := packet.NetworkLayer().NetworkFlow().Src()
	det.Logger.Println("forwarding:", src, "->", dst)
}

//
func (det *Detector) Register(s2d *pb.StationToDetector) {
	err := det.tracker.Add(s2d)
	if err != nil {
		det.Logger.Printf("error adding registration: %v", err)
	}
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

	tr := NewTracker()

	det := &Detector{
		Iface:          iface,
		FilterList:     []string{"192.168.1.104"},
		tracker:        tr,
		Logger:         logrus.New(),
		stats:          &DetectorStats{},
		StatsFrequency: 3,
	}

	det.Run()
}
