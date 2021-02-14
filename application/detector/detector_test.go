package main

import (
	"fmt"
	"net"
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

func TestDetectorTagLog(t *testing.T) {
	tr := &mockTracker{}
	errMsg := "Throws Error"

	logger, hook := test.NewNullLogger()
	det := &Detector{
		tracker: tr,
		Logger:  logger,
		tags:    []string{},
	}

	pkt := getPacket()

	det.checkForTags(pkt)

	require.Equal(t, 1, len(hook.Entries))
	require.Equal(t, logrus.InfoLevel, hook.LastEntry().Level)
	require.Equal(t, "confirmed:"+errMsg, hook.LastEntry().Message)
}
