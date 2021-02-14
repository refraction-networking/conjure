//
// Session Tracking
//
// This file is used to implement session tacking for the golang detector. There
// are a few specifics be to aware of if you are going to modify this file.
//
// Current tracking is done as a Map of string timeout details. The string is a
// derived from IP addresses of flows so that lookups can be performed quickly
// when we need to determine whether a flow is associated with a session. The
// timeouts for the session which are periodically checked and cleaned up by
// the golang Detector that (currently) instantiates this.
//
// Notes:
//  - The timeout for flows can be updated. This exists for two reasons.
//      1. if a connection exists when the timeout comes due the rule needs to
//         remain in effect until the connection is closed so that packets
//         continue to be forwarded over the DNAT tun interfaces.
//      2. If a second session is received which maps to the same key string and
//         has a longer timeout we nee to update the session to be valid until
//         the timeout of the longer session. Keep in mind that if a new
//         registration is received that has a shorter timeout we still need to
//         keep the longer timeout.
//
// - The key strings that are matched against are currently different for ipv4
//   and ipv6. In v4 the string is a concatenation of the source and the
//   destination (client and phantom) addresses. In ipv6 it is only the phantom
//   address as the chance of phantom collisions is far lower.
//      * While not currently in use we could add the destination (phantom) port
//        to the key strings if we need extra specificity. This would require an
//		  update to the StationToDetector Protobuf structure to include a u16 port.
//
// - While the rust detector ingests the StationToDetector announcements over
//   redis (so that each independent thread receives the announcement and tracks
//   independently) the golang detector is interfaced directly to the station so
//   StationToDetector announcements can happen via a direct function call to add.
//   The StationToDetector struct will be used in both the rust and golang
//   registration ingest process, and can be updated incrementally.
//
// The notes above are implemented and tested below. If you modify the code
// please make sure the tests still pass. If you modify the way this code is
// used please update the tests.

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

// Tracker interface to interact with detector session tracking.
type Tracker interface {
	Add(*pb.StationToDetector) error

	Update(string, time.Duration) error

	RemoveExpired() (int, error)

	IsRegistered(src, dst string, dstPort uint16) bool
}

// Entry provides a structure to organize the information stored for each
// registration useful to the detectors lookup.
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
	packets uint32
	bytes   uint32
}

// DefaultTracker - track and look for potential registriaons for incoming connections
// Sessions cannot be tracked by registration because we will not be
// receiving registration information in order to identify the sessions. As
// such sessions are stored as a thread safe map with keys dependent on the
// ip version:
// v4 "{}-{}", client_ip, phantom_ip
// v6 "{}", phantom_ip
//
// The value stored for each of these is a timestamp to compare for timeout.
// Note: In the future phantom port can be optionally added to the key
// string to further filter incoming connections. This is left off for now
// to allow for testing of source-refraction.
type DefaultTracker struct {
	m        sync.Mutex
	sessions map[string]*Entry
}

// NewTracker  instantiates DefaultTracker
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

// Update is used to update (increase) the time that we  consider a session
// valid for tracking purposes. Called when packets from a session are
// seen so that forwarding continues past the original registration timeout.
func (dt *DefaultTracker) Update(key string, d time.Duration) error {
	dt.m.Lock()
	defer dt.m.Unlock()

	return dt.update(key, d)
}

func (dt *DefaultTracker) update(key string, d time.Duration) error {
	if dt.sessions == nil {
		return fmt.Errorf("[DefaultTracker.Update] - nil session tracker")
	}

	entry, ok := dt.sessions[key]
	if ok {
		entry.timeout = time.Now().Add(d)
	}
	return nil
}

// RemoveExpired garbage collects all entries that have passed their lifetime
// timeout and not received an update to their connection timeout
// (i.e. they are unused).
func (dt *DefaultTracker) RemoveExpired() (int, error) {
	dt.m.Lock()
	defer dt.m.Unlock()

	return dt.removeExpired()
}

func (dt *DefaultTracker) removeExpired() (int, error) {
	if dt.sessions == nil {
		return 0, fmt.Errorf("[DefaultTracker.removeExpired] - nil session tracker")
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

// IsRegistered check based on details availale from captured traffic if a
// connection is potentially associated with a known registration.
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
		packets:          0,
		bytes:            0,
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
