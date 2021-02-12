package main

import (
	"testing"

	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/stretchr/testify/assert"
)

func TestDetectorTracker(t *testing.T) {
	tr := NewTracker()

	testsGood := []*pb.StationToDetector{
		&pb.StationToDetector{},
		&pb.StationToDetector{},
	}

	// testsErr := []*pb.StationToDetector{}

	for _, entry := range testsGood {
		print(entry)

		err := tr.Add(entry)
		assert.Nil(t, err)

		// assert.Equal(true, tr.isRegistered(entry.Src, entry.Dst, entry.DstPort))
	}
}
