package main

import (
	"fmt"
	"sync"
	"time"

	pb "github.com/refraction-networking/gotapdance/protobuf"
)

type Tracker interface {
	Add(*pb.StationToDetector) error

	Update(time.Duration) error

	RemoveExpired() error

	IsRegistered(src, dst string, dstPort uint16) bool
}

type Entry struct {
	timeout          time.Time
	originalTimeout  time.Time
	originalDuration time.Duration

	// This has potential to be a missleading statistic. It does not count
	// connections to a unique registration (i.e. by IDString). If two separate
	// registrations collide on the proper features they will both update this
	// Entry. So it will count connections for both. ClientIPs arenever logged
	// so we don't currently have a logging way of knowing how many collisions
	// there are.
	connections uint32
}

type DefaultTracker struct {
	m        sync.Mutex
	sessions map[string]*Entry
}

func NewTracker() Tracker {
	var sessions = make(map[string]*Entry)
	return &DefaultTracker{
		sessions: sessions,
	}
}

func (dt *DefaultTracker) Add(*pb.StationToDetector) error {
	if dt.sessions == nil {
		dt.sessions = make(map[string]*Entry)
	}

	return fmt.Errorf("Not Implemented yet")
}

func (dt *DefaultTracker) Update(time.Duration) error {
	if dt.sessions == nil {
		return fmt.Errorf("DefaultTracker.Update - nil session tracker.")
	}
	return fmt.Errorf("Not Implemented yet")
}

func (dt *DefaultTracker) RemoveExpired() error {
	if dt.sessions == nil {
		return fmt.Errorf("DefaultTracker.Update - nil session tracker.")
	}
	return fmt.Errorf("Not Implemented yet")
}

func (dt *DefaultTracker) IsRegistered(src, dst string, dstPort uint16) bool {
	if dt.sessions == nil {
		return false
	}
	return true
}
