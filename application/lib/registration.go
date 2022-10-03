package lib

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	golog "log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	lt "github.com/refraction-networking/conjure/application/liveness"
	"github.com/refraction-networking/conjure/application/log"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"google.golang.org/protobuf/proto"
)

// DETECTOR_REG_CHANNEL is a constant that defines the name of the redis map that we
// send validated registrations over in order to notify all detector cores.
const DETECTOR_REG_CHANNEL string = "dark_decoy_map"

// AES_GCM_TAG_SIZE the size of the aesgcm tag used when generating the client to
// station message.
const AES_GCM_TAG_SIZE = 16

// Transport defines the interface for the manager to interface with variable
// transports that wrap the traffic sent by clients.
type Transport interface {
	// The human-friendly name of the transport.
	Name() string

	// The prefix used when including this transport in logs.
	LogPrefix() string

	// GetIdentifier takes in a registration and returns an identifier
	// for it. This identifier should be unique for each registration on
	// a given phantom; registrations on different phantoms can have the
	// same identifier.
	GetIdentifier(*DecoyRegistration) string
}

// WrappingTransport describes any transport that is able to passively
// listen to incoming network connections and identify itself, then actively
// wrap the connection.
type WrappingTransport interface {
	Transport

	// WrapConnection attempts to wrap the given connection in the transport.
	// It takes the information gathered so far on the connection in data, attempts
	// to identify itself, and if it positively identifies itself wraps the connection
	// in the transport, returning a connection that's ready to be used by others.
	//
	// If the returned error is nil or non-nil and non-{ transports.ErrTryAgain, transports.ErrNotTransport },
	// the caller may no longer use data or conn.
	//
	// Implementations should not Read from conn unless they have positively identified
	// that the transport exists and are in the process of wrapping the connection.
	//
	// Implementations should not Read from data unless they are are attempting to
	// wrap the connection. Use data.Bytes() to get all of the data that has been
	// seen on the connection.
	//
	// If implementations cannot tell if the transport exists on the connection (e.g. there
	// hasn't yet been enough data sent to be conclusive), they should return
	// transports.ErrTryAgain. If the transport can be conclusively determined to not
	// exist on the connection, implementations should return transports.ErrNotTransport.
	WrapConnection(data *bytes.Buffer, conn net.Conn, phantom net.IP, rm *RegistrationManager) (reg *DecoyRegistration, wrapped net.Conn, err error)
}

// ConnectingTransport describes transports that actively form an
// outgoing connection to clients to initiate the conversation.
type ConnectingTransport interface {
	Transport

	// Connect attempts to connect to the client from the phantom address
	// derived in the registration.
	Connect(context.Context, *DecoyRegistration) (net.Conn, error)
}

// RegistrationManager manages registration tracking for the station.
type RegistrationManager struct {
	registeredDecoys *RegisteredDecoys
	Logger           *log.Logger
	PhantomSelector  *PhantomIPSelector
	LivenessTester   lt.LivenessTester
}

// NewRegistrationManager returns a newly initialized registration Manager
func NewRegistrationManager() *RegistrationManager {

	logger := log.New(os.Stdout, "[REG] ", golog.Ldate|golog.Lmicroseconds)

	var ult *lt.UncachedLivenessTester = new(lt.UncachedLivenessTester)
	p, err := NewPhantomIPSelector()
	if err != nil {
		// fmt.Errorf("failed to create the PhantomIPSelector object: %v", err)
		return nil
	}
	return &RegistrationManager{
		Logger:           logger,
		registeredDecoys: NewRegisteredDecoys(),
		PhantomSelector:  p,
		LivenessTester:   ult,
	}
}

// AddTransport initializes a transport so that it can be tracked by the manager when
// clients register.
func (regManager *RegistrationManager) AddTransport(index pb.TransportType, t Transport) error {
	if regManager == nil {
		regManager = NewRegistrationManager()
	}
	if regManager.registeredDecoys == nil {
		regManager.registeredDecoys = NewRegisteredDecoys()
	}
	regManager.registeredDecoys.m.Lock()
	defer regManager.registeredDecoys.m.Unlock()

	regManager.registeredDecoys.transports[index] = t
	return nil
}

// GetWrappingTransports Returns a map of the wrapping transport types to their transports. This return value
// can be mutated freely.
func (regManager *RegistrationManager) GetWrappingTransports() map[pb.TransportType]WrappingTransport {
	m := make(map[pb.TransportType]WrappingTransport)
	regManager.registeredDecoys.m.RLock()
	defer regManager.registeredDecoys.m.RUnlock()

	for k, v := range regManager.registeredDecoys.transports {
		wt, ok := v.(WrappingTransport)
		if ok {
			m[k] = wt
		}
	}

	return m
}

// NewRegistration creates a new registration from details provided. Adds the registration
// to tracking map, But marks it as not valid.
func (regManager *RegistrationManager) NewRegistration(c2s *pb.ClientToStation, conjureKeys *ConjureSharedKeys, includeV6 bool, registrationSource *pb.RegistrationSource) (*DecoyRegistration, error) {

	phantomAddr, err := regManager.PhantomSelector.Select(
		conjureKeys.DarkDecoySeed, uint(c2s.GetDecoyListGeneration()), uint(c2s.GetClientLibVersion()), includeV6)

	if err != nil {
		return nil, fmt.Errorf("Failed to select phantom IP address: %v", err)
	}

	reg := DecoyRegistration{
		DarkDecoy:          phantomAddr,
		Keys:               conjureKeys,
		Covert:             c2s.GetCovertAddress(),
		Mask:               c2s.GetMaskedDecoyServerName(),
		Flags:              c2s.Flags,
		Transport:          c2s.GetTransport(),
		DecoyListVersion:   c2s.GetDecoyListGeneration(),
		RegistrationTime:   time.Now(),
		RegistrationSource: registrationSource,
		regCount:           0,
	}

	return &reg, nil
}

// NewRegistrationC2SWrapper creates a new registration from details provided. Adds the registration
// to tracking map, But marks it as not valid.
func (regManager *RegistrationManager) NewRegistrationC2SWrapper(c2sw *pb.C2SWrapper, includeV6 bool) (*DecoyRegistration, error) {
	c2s := c2sw.GetRegistrationPayload()

	// Generate keys from shared secret using HKDF
	conjureKeys, err := GenSharedKeys(c2sw.GetSharedSecret())
	if err != nil {
		return nil, fmt.Errorf("Failed to generate keys: %v", err)
	}

	phantomAddr, err := regManager.PhantomSelector.Select(
		conjureKeys.DarkDecoySeed, uint(c2s.GetDecoyListGeneration()), uint(c2s.GetClientLibVersion()), includeV6)

	if err != nil {
		return nil, fmt.Errorf("Failed to select phantom IP address: %v", err)
	}

	clientAddr := net.IP(c2sw.GetRegistrationAddress())

	if phantomAddr.To4() != nil && clientAddr.To4() == nil {
		// This can happen if the client chooses from a set that contains no
		// ipv6 options even if include ipv6 is enabled they will get ipv4.
		return nil, fmt.Errorf("Failed because IPv6 client chose IPv4 phantom")
	}

	regSrc := c2sw.GetRegistrationSource()
	reg := DecoyRegistration{
		DarkDecoy:          phantomAddr,
		registrationAddr:   net.IP(c2sw.GetRegistrationAddress()),
		Keys:               &conjureKeys,
		Covert:             c2s.GetCovertAddress(),
		Mask:               c2s.GetMaskedDecoyServerName(),
		Flags:              c2s.Flags,
		Transport:          c2s.GetTransport(),
		DecoyListVersion:   c2s.GetDecoyListGeneration(),
		RegistrationTime:   time.Now(),
		RegistrationSource: &regSrc,
		regCount:           0,
	}

	return &reg, nil
}

// TrackRegistration adds the registration to the map WITHOUT marking it valid.
func (regManager *RegistrationManager) TrackRegistration(d *DecoyRegistration) error {
	err := regManager.registeredDecoys.Track(d)
	if err != nil {
		return err
	}
	return nil
}

// AddRegistration officially adds the registration to usage by marking it as valid.
func (regManager *RegistrationManager) AddRegistration(d *DecoyRegistration) {

	darkDecoyAddr := d.DarkDecoy.String()
	err := regManager.registeredDecoys.register(darkDecoyAddr, d)
	if err != nil {
		regManager.Logger.Printf("Error registering decoy: %s", err)
	}
}

// RegistrationExists checks if the registration is already tracked by the manager, this is
// independent of the validity tag, this just checks to see if the registration exists.
func (regManager *RegistrationManager) RegistrationExists(reg *DecoyRegistration) bool {
	trackedReg := regManager.registeredDecoys.RegistrationExists(reg)
	return trackedReg != nil
}

// GetRegistrations returns registrations associated with a specific phantom address.
func (regManager *RegistrationManager) GetRegistrations(phantomAddr net.IP) map[string]*DecoyRegistration {
	return regManager.registeredDecoys.getRegistrations(phantomAddr)
}

// CountRegistrations counts the number of registrations tracked that are using a
// specific phantom address.
func (regManager *RegistrationManager) CountRegistrations(phantomAddr net.IP) int {
	return regManager.registeredDecoys.countRegistrations(phantomAddr)
}

// RemoveOldRegistrations garbage collects old registrations
func (regManager *RegistrationManager) RemoveOldRegistrations() {
	regManager.registeredDecoys.removeOldRegistrations(regManager.Logger)
}

// PhantomIsLive - Test whether the phantom is live using
// 8 syns which returns syn-acks from 99% of sites within 1 second.
// see  ZMap: Fast Internet-wide Scanning  and Its Security Applications
// https://www.usenix.org/system/files/conference/usenixsecurity13/sec13-paper_durumeric.pdf
//
// return:	bool	true  - host is live
//
//			false - host is not liev
//	error	reason decision was made
func (regManager *RegistrationManager) PhantomIsLive(addr string, port uint16) (bool, error) {
	return regManager.LivenessTester.PhantomIsLive(addr, port)
}

// DecoyRegistration is a struct for tracking individual sessions that are expecting or tracking connections.
type DecoyRegistration struct {
	DarkDecoy          net.IP
	registrationAddr   net.IP
	Keys               *ConjureSharedKeys
	Covert, Mask       string
	Flags              *pb.RegistrationFlags
	Transport          pb.TransportType
	RegistrationTime   time.Time
	RegistrationSource *pb.RegistrationSource
	DecoyListVersion   uint32
	regCount           int32

	// validity marks whether the registration has been validated through liveness and other checks.
	// This also denotes whether the registration has been shared with the detector.
	Valid bool
}

// String -- Print a digest of the important identifying information for this registration.
// [TODO]{priority:soon} Find a way to add the client IP to this logging for now it is logged
// in the detector associating registrant IP with shared secret.
func (reg *DecoyRegistration) String() string {
	if reg == nil {
		return "{}"
	}

	stats := struct {
		Phantom          string
		SharedSecret     string
		Covert, Mask     string
		Flags            *pb.RegistrationFlags
		Transport        pb.TransportType
		RegTime          time.Time
		DecoyListVersion uint32
		Source           *pb.RegistrationSource
	}{
		Phantom:          reg.DarkDecoy.String(),
		SharedSecret:     hex.EncodeToString(reg.Keys.SharedSecret),
		Mask:             reg.Mask,
		Flags:            reg.Flags,
		Transport:        reg.Transport,
		RegTime:          reg.RegistrationTime,
		DecoyListVersion: reg.DecoyListVersion,
		Source:           reg.RegistrationSource,
	}
	regStats, err := json.Marshal(stats)
	if err != nil {
		return fmt.Sprintf("%v", reg.String())
	}
	return string(regStats)
}

// Length of the registration ID for logging
var regIDLen = 16

// IDString - return a short version of the id (HMAC-ID) of a registration for logging
func (reg *DecoyRegistration) IDString() string {
	var xid []string

	for i := 0; i < regIDLen; i++ {
		xid = append(xid, "0")
	}
	nilID := strings.Join(xid, "")

	if reg == nil || reg.Keys == nil {

		return nilID
	}

	secret := make([]byte, hex.EncodedLen(len(reg.Keys.SharedSecret)))
	n := hex.Encode(secret, reg.Keys.SharedSecret)
	if n < 16 {
		return nilID
	}
	return string(secret[:regIDLen])
}

// GenerateClientToStation creates a clientToStation struct. This is used in registration sharing
// between stations where the station notifies other stations of a registration.
func (reg *DecoyRegistration) GenerateClientToStation() *pb.ClientToStation {
	v4 := false
	if reg.DarkDecoy.To4() != nil {
		v4 = true
	}
	v6 := !v4

	//[reference] Generate ClientToStation protobuf
	// transition := pb.C2S_Transition_C2S_SESSION_INIT
	initProto := &pb.ClientToStation{
		CovertAddress:       &reg.Covert,
		DecoyListGeneration: &reg.DecoyListVersion,
		V6Support:           &v6,
		V4Support:           &v4,
		Transport:           &reg.Transport,
	}

	for (proto.Size(initProto)+AES_GCM_TAG_SIZE)%3 != 0 {
		initProto.Padding = append(initProto.Padding, byte(0))
	}

	return initProto
}

// GenerateC2SWrapper creates a C2SWrapper struct. This is used in registration sharing between
// stations where the station notifies other stations of a registration.
func (reg *DecoyRegistration) GenerateC2SWrapper() *pb.C2SWrapper {
	boolHolder := true
	c2s := reg.GenerateClientToStation()

	if c2s.GetFlags() == nil {
		c2s.Flags = &pb.RegistrationFlags{
			Prescanned: &boolHolder,
		}
	} else {
		c2s.Flags.Prescanned = &boolHolder
	}

	source := pb.RegistrationSource_DetectorPrescan

	protoPayload := &pb.C2SWrapper{
		SharedSecret:        reg.Keys.SharedSecret,
		RegistrationPayload: c2s,
		RegistrationSource:  &source,
		RegistrationAddress: []byte(reg.registrationAddr),
	}
	return protoPayload
}

// PreScanned returns true if a regisration has been pre-scanned - i.e scanned by another station
// before being shared
func (reg *DecoyRegistration) PreScanned() bool {
	if reg == nil || reg.Flags == nil {
		return false
	}
	return reg.Flags.GetPrescanned()
}

// GetRegistrationAddress returns the address that was used to create this registration. This should
// almost never be used - it exists to get the address for debugging and for logging misbehaving
// client IPs.
func (reg *DecoyRegistration) GetRegistrationAddress() string {
	return reg.registrationAddr.String()
}

// DecoyTimeout contains all fields required to track registration validity / expiration.
type DecoyTimeout struct {
	decoy            string
	identifier       string
	registrationTime time.Time
	regID            string
}

// RegisteredDecoys provides a container stuct for tracking all registrations and their expiration.
type RegisteredDecoys struct {
	// decoys will be a map from decoy_ip to a:
	// map from "registration identifier" to registration.
	// This is one component of what allows a transport to
	// identify a registration; its meaning will differ
	// between transports.
	decoys map[string]map[string]*DecoyRegistration

	transports map[pb.TransportType]Transport

	decoysTimeouts map[string]*DecoyTimeout
	m              sync.RWMutex
}

// NewRegisteredDecoys returns a new struct with which to track registrations.
func NewRegisteredDecoys() *RegisteredDecoys {
	return &RegisteredDecoys{
		decoys:         make(map[string]map[string]*DecoyRegistration),
		transports:     make(map[pb.TransportType]Transport),
		decoysTimeouts: make(map[string]*DecoyTimeout),
	}
}

// Track informs the registered decoys struct of a new registration to track.
//
// For use outside of this struct (so there are no data races.)
func (r *RegisteredDecoys) Track(d *DecoyRegistration) error {
	r.m.Lock()
	defer r.m.Unlock()

	return r.track(d)
}

// For use inside of this struct (so no deadlocks on struct mutex)
func (r *RegisteredDecoys) track(d *DecoyRegistration) error {

	// Is the registration is already tracked.
	if reg := r.registrationExists(d); reg != nil {
		// update tracked registration with new information if any
		reg.regCount++
		return nil
	}

	t, ok := r.transports[d.Transport]
	if !ok {
		return fmt.Errorf("unknown transport %d", d.Transport)
	}

	phantomAddr := d.DarkDecoy.String()
	identifier := t.GetIdentifier(d)

	// Newly tracked registrations are not valid and have only been seen once.
	d.regCount = 1
	d.Valid = false

	_, exists := r.decoys[phantomAddr]
	if !exists {
		r.decoys[phantomAddr] = map[string]*DecoyRegistration{}
	}

	r.decoys[phantomAddr][identifier] = d

	newtimeout := &DecoyTimeout{
		decoy:            phantomAddr,
		identifier:       identifier,
		registrationTime: time.Now(),
		regID:            d.IDString(),
	}
	r.decoysTimeouts[d.IDString()+phantomAddr] = newtimeout

	return nil
}

func (r *RegisteredDecoys) register(darkDecoyAddr string, d *DecoyRegistration) error {

	r.m.Lock()
	defer r.m.Unlock()

	reg := r.registrationExists(d)
	if reg == nil {
		// Track unknown registration
		err := r.track(d)
		if err != nil {
			return err
		}

		// Get a reference to the registration so we can update the valid tag.
		reg = r.registrationExists(d)
		if reg == nil {
			return fmt.Errorf("failed to track and register %s with unknown error", d.IDString())
		}
	}

	if reg.Valid {
		// Registration has already been shared with the detector
		return nil
	}

	reg.Valid = true
	registerForDetector(reg)

	return nil
}

func (r *RegisteredDecoys) getRegistrations(darkDecoyAddr net.IP) map[string]*DecoyRegistration {
	darkDecoyAddrStatic := darkDecoyAddr.String()
	r.m.RLock()
	defer r.m.RUnlock()

	original := r.decoys[darkDecoyAddrStatic]

	regs := make(map[string]*DecoyRegistration)
	for k, v := range original {
		if v.Valid {
			// only return valid registration so we don't allow connections to a
			// registration that has not been validated yet.
			regs[k] = v
		}
	}

	return regs
}

// TotalRegistrations return the total number of current registrations
func (r *RegisteredDecoys) TotalRegistrations() int {
	r.m.RLock()
	defer r.m.RUnlock()

	return r.totalRegistrations()
}

func (r *RegisteredDecoys) totalRegistrations() int {

	total := 0
	for _, regSet := range r.decoys {
		total += len(regSet)
	}
	return total
}

func (r *RegisteredDecoys) countRegistrations(darkDecoyAddr net.IP) int {
	ddAddrStr := darkDecoyAddr.String()
	r.m.RLock()
	defer r.m.RUnlock()

	regs, exists := r.decoys[ddAddrStr]
	if !exists {
		return 0
	}
	return len(regs)
}

// RegistrationExists - For use outside of this struct only (so there are no data races.)
func (r *RegisteredDecoys) RegistrationExists(d *DecoyRegistration) *DecoyRegistration {
	r.m.RLock()
	defer r.m.RUnlock()

	return r.registrationExists(d)

}

// For use inside of this struct (so no deadlocks on struct mutex)
func (r *RegisteredDecoys) registrationExists(d *DecoyRegistration) *DecoyRegistration {

	t, ok := r.transports[d.Transport]
	if !ok {
		return nil
	}

	identifier := t.GetIdentifier(d)

	phantomAddr := d.DarkDecoy.String()

	_, exists := r.decoys[phantomAddr]
	if !exists {
		return nil
	}

	reg, exists := r.decoys[phantomAddr][identifier]
	if !exists {
		return nil
	}

	return reg
}

type regExpireLogMsg struct {
	DecoyAddr  string
	Reg2expire int64
	RegID      string
	RegCount   int32
}

func (r *RegisteredDecoys) getExpiredRegistrations() []string {
	r.m.RLock()
	defer r.m.RUnlock()

	const regTimeout = time.Hour * 6
	var cutoff = time.Now().Add(-regTimeout)
	var expiredRegTimeoutIndices = []string{}

	for idx, decoyTimeout := range r.decoysTimeouts {
		if decoyTimeout.registrationTime.Before(cutoff) {
			// if a registration was received before the cutoff time add it
			// to the list of registrations to be removed.
			expiredRegTimeoutIndices = append(expiredRegTimeoutIndices, idx)
		}
	}

	return expiredRegTimeoutIndices
}

func (r *RegisteredDecoys) removeRegistration(index string) *regExpireLogMsg {
	r.m.Lock()
	defer r.m.Unlock()

	expiredReg := r.decoysTimeouts[index]
	expiredRegObj, ok := r.decoys[expiredReg.decoy][expiredReg.identifier]
	if !ok {
		return nil
	}

	stats := &regExpireLogMsg{
		DecoyAddr:  expiredReg.decoy,
		Reg2expire: int64(time.Since(expiredReg.registrationTime) / time.Millisecond),
		RegID:      expiredReg.regID,
		RegCount:   expiredRegObj.regCount,
	}

	if expiredRegObj.Valid {
		// Update stats
		Stat().ExpireReg(expiredRegObj.DecoyListVersion, expiredRegObj.RegistrationSource)
	}

	// remove from timeout tracking
	delete(r.decoysTimeouts, index)

	// remove from decoy tracking
	delete(r.decoys[expiredReg.decoy], expiredReg.identifier)

	// if no more registration exist for this phantom clean up
	if len(r.decoys[expiredReg.decoy]) == 0 {
		delete(r.decoys, expiredReg.decoy)
	}

	return stats
}

// This whole process of tracking timeouts and registrations separately
// makes less and less sense every time I come back to it.
// Note: please try to limit duration that this process is capable of taking the
// lock on the RegisteredDecoys mutex to prevent thread locking.
func (r *RegisteredDecoys) removeOldRegistrations(logger *log.Logger) {
	var expiredRegTimeoutIndices = r.getExpiredRegistrations()

	logger.Printf("cleansing registrations - registrations: %d, timeouts: %d, expired: %d",
		r.TotalRegistrations(), len(r.decoysTimeouts), len(expiredRegTimeoutIndices))

	for _, idx := range expiredRegTimeoutIndices {

		stats := r.removeRegistration(idx)
		if stats != nil {
			statsStr, _ := json.Marshal(stats)
			logger.Printf("expired registration %s", statsStr)
		}
	}
}

// **NOTE**: If you mess with this function make sure the
// session tracking tests on the detector side do what you expect
// them to do. (conjure/src/session.rs)
func registerForDetector(reg *DecoyRegistration) {
	client := getRedisClient()
	if client == nil {
		fmt.Printf("couldn't connect to redis")
		return
	}

	duration := uint64(6 * time.Hour.Nanoseconds())
	src := reg.registrationAddr.String()
	phantom := reg.DarkDecoy.String()
	msg := &pb.StationToDetector{
		PhantomIp: &phantom,
		ClientIp:  &src,
		TimeoutNs: &duration,
	}

	s2d, err := proto.Marshal(msg)
	if err != nil {
		// throw(fit)
		return
	}

	ctx := context.Background()
	client.Publish(ctx, DETECTOR_REG_CHANNEL, string(s2d))
}
