package main

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
)

// =============[ Mocking Tracker ]=============[

type mockTracker struct {
	addMock           func(*pb.StationToDetector) error
	updateMock        func(string, time.Duration) error
	removeExpiredMock func() (int, error)
	isRegisteredMock  func(src, dst string, dstPort uint16) bool
}

func (m *mockTracker) Add(s2d *pb.StationToDetector) error {
	return m.addMock(s2d)
}
func (m *mockTracker) Update(key string, d time.Duration) error {
	return m.updateMock(key, d)
}
func (m *mockTracker) RemoveExpired() (int, error) {
	return m.removeExpiredMock()
}
func (m *mockTracker) IsRegistered(src, dst string, dstPort uint16) bool {
	return m.isRegisteredMock(src, dst, dstPort)
}

// =============[ Packet Generation ]=============[

func getPacket() gopacket.Packet {
	var buffer gopacket.SerializeBuffer
	var options gopacket.SerializeOptions

	rawBytes := []byte{10, 20, 30}
	// This time lets fill out some information
	ipLayer := &layers.IPv4{
		SrcIP: net.IP{127, 0, 0, 1},
		DstIP: net.IP{8, 8, 8, 8},
	}
	ethernetLayer := &layers.Ethernet{
		SrcMAC: net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
		DstMAC: net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(4321),
		DstPort: layers.TCPPort(80),
	}
	// And create the packet with the layers
	buffer = gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		tcpLayer,
		gopacket.Payload(rawBytes),
	)
	if err != nil {
		return nil
	}
	rawPacket := buffer.Bytes()

	return gopacket.NewPacket(
		rawPacket,
		layers.LayerTypeTCP,
		gopacket.NoCopy,
	)

}

// =============[ Tests ]=============[

func TestDetectorInitialization(t *testing.T) {

	// test error handling first
	os.Setenv("CJ_STATION_CONFIG", "/tmp/file_does_not_exist.toml")
	det, err := NewDetector()
	require.Nil(t, det)
	require.Equal(t, "failed to load config: open /tmp/file_does_not_exist.toml: no such file or directory", err.Error())

	// Test with actual test config
	os.Setenv("CJ_STATION_CONFIG", "./test/config.toml")
	det, err = NewDetector()
	require.Nil(t, err)
	require.NotNil(t, det)
}

func TestDetectorRegisterErrorLog(t *testing.T) {
	tr := &mockTracker{}
	errMsg := "Throws Error"
	tr.addMock = func(*pb.StationToDetector) error {
		return fmt.Errorf(errMsg)
	}
	logger, hook := test.NewNullLogger()
	det := &Detector{
		tracker: tr,
		Logger:  logger,
	}

	det.Register(&pb.StationToDetector{})

	require.Equal(t, 1, len(hook.Entries))
	require.Equal(t, logrus.WarnLevel, hook.LastEntry().Level)
	require.Equal(t, "error adding registration: "+errMsg, hook.LastEntry().Message)
}

func TestDetectorTagLogUDP(t *testing.T) {
	logMsg := "192.122.190.105 -> 192.168.1.104"

	logger, hook := test.NewNullLogger()
	det := &Detector{
		Config: &Config{
			// url query:   abcdefghijk.lmnopqrstuvw.xyz
			Tags: []string{"abcdefghijk"},
			Source: &DataSourceConfig{
				DataSourceType:  DataSourcePCAP,
				OfflinePcapPath: "./test/min_udp.pcap",
			},
		},
		Logger: logger,
	}

	handle, err := PacketSourceFromConfig(det.Source)
	if err != nil {
		t.Fatalf("Failed to open packet source for test: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		require.NotNil(t, packet)
		det.checkForTags(packet)
	}

	require.Equal(t, 3, len(hook.Entries))
	require.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
	require.Equal(t, "confirmed "+logMsg, hook.LastEntry().Message)
}

func TestDetectorTagLogTCP(t *testing.T) {
	logMsg := "192.122.190.105 -> 192.168.1.104"

	logger, hook := test.NewNullLogger()
	det := &Detector{
		Config: &Config{
			Tags: []string{"nginx"},
			Source: &DataSourceConfig{
				DataSourceType:  DataSourcePCAP,
				OfflinePcapPath: "./test/min.pcap",
			},
		},
		Logger: logger,
	}

	handle, err := PacketSourceFromConfig(det.Source)
	if err != nil {
		t.Fatalf("Failed to open packet source for test: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		require.NotNil(t, packet)
		det.checkForTags(packet)
	}

	require.Equal(t, 1, len(hook.Entries))
	require.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
	require.Equal(t, "confirmed "+logMsg, hook.LastEntry().Message)
}

func TestDetectorMatchForward(t *testing.T) {

	// Use PCAP Packet source -- read from registered.pcap

	// add registration from address

	// "listen for packets"

	// Make sure forward is called on the right packets.

	require.NotNil(t, nil)
}
