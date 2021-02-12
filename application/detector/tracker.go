package main

import (
	"fmt"
	"sync"
	"time"

	pb "github.com/refraction-networking/gotapdance/protobuf"
)

// SessionExtension - length to extend sessions when connections are still
// alive with connections but past timeout in the tracker.
const SessionExtension = time.Duration(3) * time.Minute

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

func (dt *DefaultTracker) Add(s2d *pb.StationToDetector) error {
	dt.m.Lock()
	defer dt.m.Unlock()

	return dt.add(s2d)
}

func (dt *DefaultTracker) add(s2d *pb.StationToDetector) error {
	if dt.sessions == nil {
		dt.sessions = make(map[string]*Entry)
	}

	key, entry, err := entryFromS2D(s2d)
	if err != nil {
		return err
	}

	dt.sessions[key] = entry

	return nil
}

func (dt *DefaultTracker) Update(t time.Duration) error {
	dt.m.Lock()
	defer dt.m.Unlock()

	return dt.update(t)
}

func (dt *DefaultTracker) update(t time.Duration) error {
	if dt.sessions == nil {
		return fmt.Errorf("DefaultTracker.Update - nil session tracker.")
	}

	return fmt.Errorf("Not Implemented yet")
}

func (dt *DefaultTracker) RemoveExpired() error {
	dt.m.Lock()
	defer dt.m.Unlock()

	return dt.removeExpired()
}

func (dt *DefaultTracker) removeExpired() error {
	if dt.sessions == nil {
		return fmt.Errorf("DefaultTracker.Update - nil session tracker.")
	}
	return fmt.Errorf("Not Implemented yet")
}

func (dt *DefaultTracker) IsRegistered(src, dst string, dstPort uint16) bool {
	dt.m.Lock()
	defer dt.m.Unlock()

	return dt.isRegistered(src, dst, dstPort)
}

func (dt *DefaultTracker) isRegistered(src, dst string, dstPort uint16) bool {
	if dt.sessions == nil {
		return false
	}
	return true
}

func entryFromS2D(s2d *pb.StationToDetector) (string, *Entry, error) {
	lifetime := time.Duration(s2d.GetTimeoutNs()) * time.Nanosecond
	entry := &Entry{
		timeout:          time.Now().Add(lifetime),
		originalTimeout:  time.Now().Add(lifetime),
		originalDuration: lifetime,
		connections:      0,
	}

	key, err := keyFromS2D(s2d)
	if err != nil {
		return "", nil, err
	}

	return key, entry, nil
}

func keyFromS2D(s2d *pb.StationToDetector) (string, error) {

	clientIP := net.ParseIP(s2d.GetClientIP())
	phantomIP := net.ParseIP(s2d.GetClientIP())

	if net.ParseIP(clientIP)
	key := fmt.Sprintf("%s-%s", , s2d.GetPhantomIp())

	return key, nil
}
