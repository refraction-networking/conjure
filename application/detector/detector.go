package detector

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	log "github.com/sirupsen/logrus"
)

// Detector implements a single thread packet capture process forming a critical
// piece of a refraction networking station. This simple detector is independent
// of the Tapdance style registration components of the more heavyweight Rust
// detector implementation and is (at present) meant purely for testing and use
// with the API based registrars.
type Detector struct {
	*Config

	// Packet ingest
	producer *Producer

	// intermediary between packet ingest and worker threads
	consumer *Consumer

	// Logger provided by initializing application.
	Logger *log.Logger

	// bool for independent thread to synchronize exit.
	exit bool

	// TODO
	// Stats tracking to mimic rust detector
	stats *DetectorStats

	// State Tracking to allow for quick map lookup and timeout tracking.
	// - We could store one tracker per thread (which would prevent them from
	// 		contending but would require N times as much storage - 1 per thread)
	// - OR we could store one and have all access it via mutex. which might
	// 		slow access times and stuff, but minimizes storage requirements.
	tracker Tracker

	// Check storage for tracked entries past timeouts
	GarbageCollect func() error
}

// NewDetector parses configuration file from default location and return a new
// Detector.
func NewDetector() (*Detector, error) {

	conf, err := GetConfig()
	if err != nil {
		return nil, err
	}

	return DetectorFromConfig(conf)
}

// DetectorFromConfig return Detector if the configuration was instantiated
// independently, or if was parsed elsewhere.
func DetectorFromConfig(conf *Config) (*Detector, error) {

	var tr = NewTracker()

	var det = &Detector{
		Config:  conf,
		tracker: tr,
		stats:   &DetectorStats{},
	}
	return det, nil
}

// Run sets the detector running, capturing traffic and processing checking for
// connections associated with registrations.
// TODO: Multithread this function
func (det *Detector) Run(ctx context.Context) {

	// Open packet reader in promiscuous mode.
	packetDataSource, err := PacketSourceFromConfig(det.Source)
	// packetDataSource, err := pcap.OpenLive(det.Iface, buffer, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer packetDataSource.Close()

	//Generate and Apply filters
	filter := generateFilters(det.FilterList)
	if err := packetDataSource.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	go det.StatsThread(ctx)
	go det.CleanupThread(ctx)

	wg := &sync.WaitGroup{}
	// Start workers and Add [workerPoolSize] to WaitGroup
	wg.Add(det.Workers)
	for i := 0; i < det.Workers; i++ {
		go det.consumer.workerFunc(wg, i, det.handlePacket)
	}

	// // Actually process packets
	// source := gopacket.NewPacketSource(packetDataSource, packetDataSource.LinkType())

	// // To multithread source is actually a channel that you could pass to
	// // workers. The workers would just then need to read `packet. ok` out of
	// // the channel.
	// // https://www.reddit.com/r/golang/comments/4ec2gu/hung_up_on_gopacket/
	// for packet := range source.Packets() {
	// 	det.handlePacket(packet)
	// }

	det.exit = true
	wg.Wait()
	det.Logger.Printf("Detector Shutting Down\n")
}

// StatsThread preiodically logs  numerical metrics for performance on the station.
func (det *Detector) StatsThread(ctx context.Context) {
	for {
		det.Logger.Printf("stats %s", det.stats.Report())
		det.stats.Reset()

		select {
		case <-ctx.Done():
			return
		default:
			time.Sleep(time.Second * time.Duration(det.StatsFrequency))
		}
	}
}

// CleanupThread preiodically run cleanup for detector session tracking.
func (det *Detector) CleanupThread(ctx context.Context) {
	for {
		det.Logger.Printf("stats %s", det.stats.Report())
		det.tracker.RemoveExpired()
		// TODO: Fix this
		if det.exit {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
			time.Sleep(time.Second * time.Duration(det.CleanupFrequency))
		}
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
		key, err := keyFromParts(dst.String(), src.String(), dstPort)
		if err != nil {
			det.Logger.Warn("Error looking up connection", err)
			return
		}
		det.tracker.Update(key, SessionExtension)
	}
}

// Current stations check packets for tags (UDP specifically to check DNS)
func (det *Detector) checkForTags(packet gopacket.Packet) {
	if packet == nil {
		return
	} else if packet.ApplicationLayer() == nil {
		return
	}
	for _, tag := range det.Tags {
		if bytes.Contains(packet.ApplicationLayer().Payload(), []byte(tag)) {
			dst := packet.NetworkLayer().NetworkFlow().Dst()
			src := packet.NetworkLayer().NetworkFlow().Src()
			det.Logger.Println("confirmed", src, "->", dst)
			return
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

// Register tracks a registration for quick lookup on the data plane
// (specifically handling packet ingest and forwaring).
func (det *Detector) Register(s2d *pb.StationToDetector) {
	err := det.tracker.Add(s2d)
	if err != nil {
		det.Logger.Warnf("error adding registration: %v", err)
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

// ===============[ Consumer! ]===============

// Consumer - takes jobs and runs
type Consumer struct {
	ingestChan chan gopacket.Packet
	jobsChan   chan gopacket.Packet
}

// callbackFunc is invoked each time the external lib passes an event to us.
func (c Consumer) callbackFunc(event gopacket.Packet) {
	c.ingestChan <- event
}

// workerFunc starts a single worker function that will range on the jobsChan
// until that channel closes.
func (c Consumer) workerFunc(wg *sync.WaitGroup, index int, handlePacket func(gopacket.Packet)) {
	defer wg.Done()

	fmt.Printf("Worker %d starting\n", index)
	for packet := range c.jobsChan {
		handlePacket(packet)
	}
	fmt.Printf("Worker %d interrupted\n", index)
}

// startConsumer acts as the proxy between the ingestChan and jobsChan, with a
// select to support graceful shutdown.
func (c Consumer) startConsumer(ctx context.Context) {
	for {
		select {
		case job := <-c.ingestChan:
			c.jobsChan <- job
		case <-ctx.Done():
			fmt.Println("Consumer received cancellation signal, closing jobsChan!")
			close(c.jobsChan)
			fmt.Println("Consumer closed jobsChan")
			return
		}
	}
}

// ===============[ Producer ]===============

// Producer simulates an external library that invokes the
// registered callback when it has new data for us once per 100ms.
type Producer struct {
	dataSource DataSource
	// dataSource   gopacket.PacketDataSource
	callbackFunc func(event gopacket.Packet)
}

func (p Producer) start() {
	// Actually process packets
	source := gopacket.NewPacketSource(p.dataSource, p.dataSource.LinkType())

	for packet := range source.Packets() {
		// det.handlePacket(packet)
		p.callbackFunc(packet)

	}
}
