package main

import (
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestDetectorDeviceExists(t *testing.T) {
	require.Nil(t, deviceExists("lo"))
	require.NotNil(t, deviceExists("bad_device_name"))
}

func TestDetectorPacketsBasics(t *testing.T) {

	dsc := &DataSourceConfig{
		// PCAP
		OfflinePcapPath: "./test/min.pcap",

		// Iface
		Iface:   "lo",
		SnapLen: int32(1600),

		// Generator
		NumPackets: 10,
	}

	dsc.DataSourceType = DataSourcePCAP
	pktSrc, err := PacketSourceFromConfig(dsc)
	require.Nil(t, err)
	require.NotNil(t, pktSrc)
	pktSrc.Close()

	// // requires root
	// dsc.DataSourceType = DataSourceIface
	// pktSrc, err = PacketSourceFromConfig(dsc)
	// require.Nil(t, err)
	// require.NotNil(t, pktSrc)

	dsc.DataSourceType = DataSourceGenerator
	pktSrc, err = PacketSourceFromConfig(dsc)
	require.Nil(t, err)
	require.NotNil(t, pktSrc)
	pktSrc.Close()
}

func TestDetectorPacketsFromPcap(t *testing.T) {
	// Parse pcap in `test/min.pcap`

	dsc := &DataSourceConfig{
		DataSourceType:  DataSourcePCAP,
		OfflinePcapPath: "./test/min.pcap",
	}

	pktSrc, err := PacketSourcePcap(dsc)
	require.Nil(t, err)
	require.NotNil(t, pktSrc)
	defer pktSrc.Close()

	require.Equal(t, layers.LinkTypeEthernet, pktSrc.LinkType())
}

/*
func TestDetectorPacketsIface(t *testing.T) {
	// Create temporary virtual interface using system
	// Listen on that interface and use tcpreplay to send packets from a pcap to
	// the interface to make sure interface listen works
	// - note: you will have to install tcpreplay from apt for this
	// - use pcap in `test/min.pcap`

	// Create Interface
	tap, err := taptun.OpenTap()

	// Create conf and data source
	dsc := &DataSourceConfig{
		DataSourceType: DataSourceIface,

		Iface:   tap.String(),
		SnapLen: int32(1600),
	}
	pktSrc, err := PacketSourceIface(dsc)
	require.Nil(t, err)
	require.NotNil(t, pktSrc)

	// listen for packets

	// tcpreplay packets back from "./test/min.pcap"
	if runtime.GOOS == "windows" {
		t.Log("Can't Execute this on a windows machine")
		return
	}

	err = replayPackets("./test/min.pcap", dsc.Iface)
	require.Nil(t, err)

	// Check packets
}

func replayPackets(pcapPath string, iface string) (err error) {
	tcpreplay, err := exec.Command("which", "tcpreplay").Output()
	if err != nil || tcpreplay == nil {
		return fmt.Errorf("error finding tcpreplay: %s", err)
	}

	_, err = exec.Command(string(tcpreplay), "-i", iface, pcapPath).Output()
	if err != nil {
		return fmt.Errorf("error replaying packets: %s", err)
	}

	return nil
}
*/
