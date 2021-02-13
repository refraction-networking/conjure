package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	pb "github.com/refraction-networking/gotapdance/protobuf"
)

// SessionExtension - length to extend sessions when connections are still
// alive with connections but past timeout in the tracker.
const SessionExtension = time.Duration(3) * time.Minute

// DefaultPort is the current default port that connections will come int on.
// If in the future we want to filter by port for certain registrations/sessions
// we can substitute that in where this is at.
const DefaultPort = 443

type Tracker interface {
	Add(*pb.StationToDetector) error

	Update(string, time.Duration) error

	RemoveExpired() (int, error)

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

	key, newEntry, err := entryFromS2D(s2d)
	if err != nil {
		return err
	}

	// Only add if it extends the timeout or doesn't exist already.
	existingEntry, ok := dt.sessions[key]
	if !ok {
		dt.sessions[key] = newEntry
		return nil
	}

	if existingEntry.timeout.Before(newEntry.timeout) {
		dt.update(key, newEntry.originalDuration)
	}

	return nil
}

func (dt *DefaultTracker) Update(key string, d time.Duration) error {
	dt.m.Lock()
	defer dt.m.Unlock()

	return dt.update(key, d)
}

func (dt *DefaultTracker) update(key string, d time.Duration) error {
	if dt.sessions == nil {
		return fmt.Errorf("DefaultTracker.Update - nil session tracker.")
	}

	entry, ok := dt.sessions[key]
	if ok {
		entry.timeout = time.Now().Add(d)
	}
	return nil
}

func (dt *DefaultTracker) RemoveExpired() (int, error) {
	dt.m.Lock()
	defer dt.m.Unlock()

	return dt.removeExpired()
}

func (dt *DefaultTracker) removeExpired() (int, error) {
	if dt.sessions == nil {
		return 0, fmt.Errorf("DefaultTracker.Update - nil session tracker.")
	}
	var count = 0
	var now = time.Now()
	for key, entry := range dt.sessions {
		if entry.timeout.Before(now) {
			count++
			delete(dt.sessions, key)
		}
	}
	return count, nil
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

	key, err := keyFromParts(src, dst, dstPort)
	if err != nil {
		return false
	}

	_, ok := dt.sessions[key]
	return ok
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

	return keyFromParts(s2d.GetClientIp(), s2d.GetPhantomIp(), DefaultPort)
}

func keyFromParts(client string, phantom string, dstPort uint16) (string, error) {

	phantomIP := net.ParseIP(phantom)
	if phantomIP == nil {
		return "", fmt.Errorf("Invalid phantom address")
	}

	clientIP := net.ParseIP(client)
	if clientIP == nil {
		if phantomIP.To4() == nil {
			clientIP = net.ParseIP("::1")
		} else {
			return "", fmt.Errorf("Invalid client address")
		}
	}

	// If the phantom is v4 and we have no IPv4 client address we cant track
	// the session.
	if (phantomIP.To4() != nil) && (clientIP.To4() == nil) {
		return "", fmt.Errorf("Client/Phantom v4/v6 mismatch")
	}

	var key = ""
	if phantomIP.To4() == nil {
		key = fmt.Sprintf("%s", phantomIP)
	} else {
		key = fmt.Sprintf("%s-%s", clientIP, phantomIP)
	}

	return key, nil
}

func s2ns(d time.Duration) uint64 {
	return uint64(d) / uint64(time.Nanosecond)
}
