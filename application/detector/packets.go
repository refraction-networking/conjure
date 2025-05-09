package detector

// This file allows us to parse a config file for parameters needed to open /
// connect to / parse a Packet Data Source. A gopacket.PacketDataSource is
// explicitly returned because that is what is required by
// gopacket.NewPacketSource which takes in packets and splits them to workers.
//

import (
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PacketSourceType defines enum of available data source types.
type PacketSourceType string

const (
	// DataSourcePCAP is a configured pcap reader data source
	DataSourcePCAP PacketSourceType = "pcap"

	// DataSourceIface is a configured live interface capture data source
	DataSourceIface = "iface"

	// DataSourceGenerator is a configured packet generator data source
	// [TODO]
	DataSourceGenerator = "generator"

	// DataSourcePFRing is a configured pf_ring source for ingesting packets
	// using cgo to wrap libpfring.h.
	// [TODO]
	DataSourcePFRing = "pfring"
)

// DataSourceConfig contains all of the individual pieces to instantiate any one
// of the packet sources and a string field to indicate which type to create.
type DataSourceConfig struct {
	DataSourceType PacketSourceType `toml:"data_source_type"`

	// ---------[ PacketSourceIface parameters ]---------
	Iface string `toml:"iface"`
	// the maximum size to read for each packet (snaplen) on live iface,
	SnapLen int32 `toml:"snap_length"`

	// ---------[ PacketSourcePcap parameters ]---------
	OfflinePcapPath string `toml:"offline_pcap_path"`

	// -------------[ Generator Parameters ]------------
	NumPackets uint64 `toml:"num_packets"`
}

// DataSource descrive the interface allowing us to merge the requirements of
// gopacket.PacketDataSource with the practicality of pcap.Handle
type DataSource interface {
	gopacket.PacketDataSource

	Close()

	SetBPFFilter(string) error

	LinkType() layers.LinkType
}

// PacketSourceFromConfig returns a configured gopacket.PacketDataSource based
// on configuration specified by data source type.
func PacketSourceFromConfig(conf *DataSourceConfig) (DataSource, error) {
	switch conf.DataSourceType {
	case DataSourcePCAP:
		return PacketSourcePcap(conf)
	case DataSourceIface:
		return PacketSourceIface(conf)
	case DataSourceGenerator:
		return PacketSourceGenerator(conf)
	default:
		return nil, fmt.Errorf("Unrecognized Data Source Type")
	}
}

// PacketSourcePcap opens a file to read pcap packets based on configuration.
func PacketSourcePcap(conf *DataSourceConfig) (DataSource, error) {
	return pcap.OpenOffline(conf.OfflinePcapPath)
}

// PacketSourceIface opens packet reader in promiscuous mode based on configuration.
func PacketSourceIface(conf *DataSourceConfig) (DataSource, error) {
	if err := deviceExists(conf.Iface); err != nil {
		return nil, fmt.Errorf("Unable to find device '%s': %v", conf.Iface, err)
	}
	// the maximum size to read for each packet (snaplen),
	return pcap.OpenLive(conf.Iface, conf.SnapLen, false, pcap.BlockForever)
}

// PacketSourceGenerator returns a PacketGenerator based on configuration.
func PacketSourceGenerator(conf *DataSourceConfig) (DataSource, error) {
	return OpenGenerator(conf.NumPackets)
}

// =================[ Packet Generator ]=================
// =======================[ TODO ]=======================

// PacketGenerator allows programatic generation of Packets to test with the
// station.
// PacketGeneration specifics:
// 	- Generate using thread(s) into a queue
//  - getNextBufPtrLocked returns the next packet out of the queue.
type PacketGenerator struct {
	// Config Params
	number uint64

	mu     sync.Mutex
	bufptr *uint8
}

// OpenGenerator returns a Packet Generator DataSource that should work with the
// gopacket PacketDataSource interface.
func OpenGenerator(numPackets uint64) (DataSource, error) {
	var pg = &PacketGenerator{
		number: numPackets,
	}
	return pg, nil
}

// ReadPacketData returns the next packet read from the pcap handle, along with an error
// code associated with that packet.  If the packet is read successfully, the
// returned error is nil.
func (pg *PacketGenerator) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	err = pg.getNextBufPtrLocked(&ci)
	if err == nil {
		// // TODO
		// data = make([]byte, ci.CaptureLength)
		// copy(data, (*(*[1 << 30]byte)(unsafe.Pointer(pg.bufptr)))[:])
		return
	}
	// // TODO
	// pg.mu.Unlock()
	// if err == pcap.NextErrorTimeoutExpired {
	// 	runtime.Gosched()
	// }
	return
}

// generate and return the next packet
func (pg *PacketGenerator) getNextBufPtrLocked(ci *gopacket.CaptureInfo) error {
	return fmt.Errorf("not yet implemented")
}

// Close cleans up and shuts down the generator
func (pg *PacketGenerator) Close() {
	//Close Down!
}

// SetBPFFilter could add filtering rules to the generated packet. For now this
// does nothing, since we can just __not generate those packets__
func (pg *PacketGenerator) SetBPFFilter(string) error {
	// Do nothing
	return nil
}

// LinkType return the layer that the link works in, since this is a generator
// this could be flexible.
func (pg *PacketGenerator) LinkType() layers.LinkType {
	return layers.LinkTypeEthernet
}

func deviceExists(name string) error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}

	for _, device := range devices {
		if device.Name == name {
			return nil
		}
	}
	return fmt.Errorf("Unable to find device '%s'", name)
}
