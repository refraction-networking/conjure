package lib

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	golog "log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/refraction-networking/conjure/pkg/station/geoip"
	"github.com/refraction-networking/conjure/pkg/station/liveness"
	"github.com/refraction-networking/conjure/pkg/station/log"

	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
)

// DETECTOR_REG_CHANNEL is a constant that defines the name of the redis map that we
// send validated registrations over in order to notify all detector cores.
const DETECTOR_REG_CHANNEL string = "dark_decoy_map"

// AES_GCM_TAG_SIZE the size of the aesgcm tag used when generating the client to
// station message.
const AES_GCM_TAG_SIZE = 16

// RegistrationManager manages registration tracking for the station.
type RegistrationManager struct {
	*RegConfig
	*RegistrationStats

	registeredDecoys *RegisteredDecoys
	Logger           *log.Logger
	PhantomSelector  *PhantomIPSelector
	LivenessTester   liveness.Tester
	GeoIP            geoip.Database

	// ingestChan is included here so that the capacity and use is available to
	// stats
	ingestChan <-chan interface{}
}

// NewRegistrationManager returns a newly initialized registration Manager
func NewRegistrationManager(conf *RegConfig) *RegistrationManager {

	logger := log.New(os.Stdout, "[REG] ", golog.Ldate|golog.Lmicroseconds)

	lt, err := liveness.New(conf.LivenessConfig())
	if err != nil {
		logger.Fatal(err)
	}

	p, err := NewPhantomIPSelector()
	if err != nil {
		logger.Errorf("failed to create the PhantomIPSelector object: %v", err)
		return nil
	}

	geoipDB, err := geoip.New(conf.DBConfig)
	if errors.Is(err, geoip.ErrMissingDB) {
		// if a database is missing, log to warm, but functionality should be the same
		logger.Warn(err)
	} else if err != nil {
		logger.Errorf("failed to create geoip database: %v", err)
		return nil
	}

	return &RegistrationManager{
		RegConfig:         conf,
		RegistrationStats: newRegistrationStats(),
		Logger:            logger,
		registeredDecoys:  NewRegisteredDecoys(),
		PhantomSelector:   p,
		LivenessTester:    lt,
		GeoIP:             geoipDB,
	}
}

// OnReload is meant to be used when Reloading Configuration while things are
// already running. Only reloads phantom selector and blocklists. Does not
// (yet) modify ingest worker pipeline or liveness testing configuration.
func (regManager *RegistrationManager) OnReload(conf *RegConfig) {

	// try to re-initialize the phantom selector, if error occurs log err and
	// do not update the existing PhantomSelector
	p, err := NewPhantomIPSelector()
	if err != nil {
		regManager.Logger.Errorf("failed to reload phantom subnets: %v", err)
	} else {
		regManager.PhantomSelector = p
	}

	// if we made it here via sigHUP then the RegConfig.ParseBlocklists should
	// already have been called and not erred.
	regManager.RegConfig.CovertBlocklistSubnets = conf.CovertBlocklistSubnets
	regManager.RegConfig.covertBlocklistSubnets = conf.covertBlocklistSubnets

	regManager.RegConfig.CovertBlocklistPublicAddrs = conf.CovertBlocklistPublicAddrs

	regManager.RegConfig.CovertAllowlistSubnets = conf.CovertAllowlistSubnets
	regManager.RegConfig.enableCovertAllowlist = conf.enableCovertAllowlist
	regManager.RegConfig.covertAllowlistSubnets = conf.covertAllowlistSubnets

	regManager.RegConfig.CovertBlocklistDomains = conf.CovertBlocklistDomains
	regManager.RegConfig.covertBlocklistDomains = conf.covertBlocklistDomains

	regManager.RegConfig.PhantomBlocklist = conf.PhantomBlocklist
	regManager.RegConfig.phantomBlocklist = conf.phantomBlocklist

	geoipDB, err := geoip.New(conf.DBConfig)
	if errors.Is(err, geoip.ErrMissingDB) {
		// if a database is missing, log to warm, but functionality should be the same
		regManager.Logger.Warn(err)
	} else if err != nil {
		regManager.Logger.Errorf("failed to create geoip database: %v", err)
		return
	}

	regManager.GeoIP = geoipDB
}

// AddTransport initializes a transport so that it can be tracked by the manager when
// clients register.
func (regManager *RegistrationManager) AddTransport(index pb.TransportType, t Transport) error {
	if regManager == nil {
		regManager = NewRegistrationManager(regManager.RegConfig)
	}
	if regManager.registeredDecoys == nil {
		regManager.registeredDecoys = NewRegisteredDecoys()
	}
	regManager.registeredDecoys.m.Lock()
	defer regManager.registeredDecoys.m.Unlock()

	regManager.registeredDecoys.transports[index] = t
	return nil
}

// IsEnabledTransport checks if the provided transport ID is enabled in the regisrtar
func (regManager *RegistrationManager) IsEnabledTransport(index pb.TransportType) bool {
	_, ok := regManager.registeredDecoys.transports[index]
	return ok
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

var errIncompleteReg = errors.New("incomplete registration")
var errTransportNotEnabled = errors.New("transport not enabled, or unknown")
var errBlocklistedPhantom = errors.New("blocklisted phantom - reg not serviceable")

// ValidateRegistration checks expected fields and combinations for common
// errors to prevent wasted time on registration ingest.
func (regManager *RegistrationManager) ValidateRegistration(reg *DecoyRegistration) (bool, error) {

	if reg == nil {
		return false, errIncompleteReg
	} else if reg.Keys == nil {
		return false, errIncompleteReg
	} else if reg.PhantomIp == nil {
		return false, errIncompleteReg
	} else if reg.RegistrationSource == nil {
		return false, errIncompleteReg
	} else if _, ok := regManager.registeredDecoys.transports[reg.Transport]; !ok {
		return false, errTransportNotEnabled
	} else if *reg.RegistrationSource != pb.RegistrationSource_Detector && regManager.IsBlocklistedPhantom(reg.PhantomIp) {
		return false, errBlocklistedPhantom
	}

	return true, nil
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

	darkDecoyAddr := d.PhantomIp.String()
	err := regManager.registeredDecoys.register(darkDecoyAddr, d)
	if err != nil {
		regManager.Logger.Errorf("Error registering decoy: %s", err)
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
	expired, validExpired := regManager.registeredDecoys.removeOldRegistrations(regManager.Logger)
	regManager.AddExpiredRegs(int64(expired), int64(validExpired))
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

// MarkActive indicates that an incoming connection has successfully been make
// with the registration provided in the argument.
func (regManager *RegistrationManager) MarkActive(reg *DecoyRegistration) {
	regManager.registeredDecoys.markActive(reg)
}

// Cleanup sends a signal to the detector to empty cached sessions. This ensures that the detector
// does not forward traffic for sessions that it knows about for a previous launch of the station
// that the current session doesn't know about.
func (regManager *RegistrationManager) Cleanup() {
	clearDetector()
}

// DecoyRegistration is a struct for tracking individual sessions that are expecting or tracking connections.
type DecoyRegistration struct {
	PhantomIp    net.IP
	PhantomPort  uint16
	PhantomProto pb.IPProto

	registrationAddr net.IP
	regCC            string
	regASN           uint

	Keys               *ConjureSharedKeys
	Covert, Mask       string
	Flags              *pb.RegistrationFlags
	Transport          pb.TransportType
	TransportPtr       *Transport
	TransportParams    any
	RegistrationTime   time.Time
	RegistrationSource *pb.RegistrationSource
	DecoyListVersion   uint32
	regCount           int32
	clientLibVer       uint32

	tunnelCount int64

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
		Phantom:          net.JoinHostPort(reg.PhantomIp.String(), strconv.FormatUint(uint64(reg.PhantomPort), 10)),
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
	if reg.PhantomIp.To4() != nil {
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

// GetDstPort returns the destination port of the phantom flow selected when the registration was
// created. For now there is no extra fancy-ness needed here because every valid registration will
// have selected a uint16 destination port on creation.
func (reg *DecoyRegistration) GetDstPort() uint16 {
	return reg.PhantomPort
}

// GetSrcPort returns a source port if one was registered. Currently this is not
// supported -- for now  this is intended as plumbing for potentially supporting
// seeded source port selection for the client.
func (reg *DecoyRegistration) GetSrcPort() uint16 {
	return 0
}

type regStatus int

const (
	regStatusUnused regStatus = iota // No connections using this registration have been received yet
	regStatusUsed   regStatus = iota // At least one valid connection has been received for this registration
	// regStatusInUse  regStatus = iota // future: maybe useful
)

// DecoyTimeout contains all fields required to track registration validity / expiration.
type DecoyTimeout struct {
	decoy            string
	identifier       string
	registrationTime time.Time
	regID            string
	status           regStatus
}

var defaultUnusedTimeout = 10 * time.Minute
var defaultActiveTimeout = 6 * time.Hour

// RegisteredDecoys provides a container struct for tracking all registrations and their expiration.
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

	timeoutActive time.Duration
	timeoutUnused time.Duration

	registerForDetector func(*DecoyRegistration)
	updateInDetector    func(*DecoyRegistration)
}

// NewRegisteredDecoys returns a new struct with which to track registrations.
func NewRegisteredDecoys() *RegisteredDecoys {
	return &RegisteredDecoys{
		timeoutActive:  defaultActiveTimeout,
		timeoutUnused:  defaultUnusedTimeout,
		decoys:         make(map[string]map[string]*DecoyRegistration),
		transports:     make(map[pb.TransportType]Transport),
		decoysTimeouts: make(map[string]*DecoyTimeout),
		registerForDetector: func(d *DecoyRegistration) {
			sendToDetector(d, uint64(defaultUnusedTimeout.Nanoseconds()), pb.StationOperations_New)
		},
		updateInDetector: func(d *DecoyRegistration) {
			sendToDetector(d, uint64(defaultActiveTimeout.Nanoseconds()), pb.StationOperations_Update)
		},
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

	phantomAddr := d.PhantomIp.String()
	identifier := t.GetIdentifier(d)

	// Newly tracked registrations are not valid and have only been seen once.
	d.regCount = 1
	d.Valid = false

	_, exists := r.decoys[phantomAddr]
	if !exists {
		r.decoys[phantomAddr] = map[string]*DecoyRegistration{}
	}

	r.decoys[phantomAddr][identifier] = d

	newTimeout := &DecoyTimeout{
		decoy:            phantomAddr,
		identifier:       identifier,
		registrationTime: time.Now(),
		regID:            d.IDString(),
		status:           regStatusUnused,
	}
	r.decoysTimeouts[d.IDString()+phantomAddr] = newTimeout

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
	r.registerForDetector(reg)

	return nil
}

func (r *RegisteredDecoys) markActive(d *DecoyRegistration) {

	r.m.Lock()
	defer r.m.Unlock()

	phantomAddr := d.PhantomIp.String()
	if regTimeout, ok := r.decoysTimeouts[d.IDString()+phantomAddr]; ok {
		regTimeout.status = regStatusUsed

		// Since we update the applicable timeout here, we should update that
		// timeout in the detector side.
		r.updateInDetector(d)
	}
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
	phantomAddr := d.PhantomIp.String()

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
	Valid          bool
	PhantomAddr    string
	PhantomDstPort uint
	Reg2expire     int64
	RegCount       int32

	ASN           uint   `json:",omitempty"`
	CC            string `json:",omitempty"`
	V6            bool
	Transport     string   `json:",omitempty"`
	Registrar     string   `json:",omitempty"`
	TransportOpts []string `json:",omitempty"`
	RegOpts       []string `json:",omitempty"`
	TunnelCount   uint
	Tags          []string `json:",omitempty"`
}

func (r *RegisteredDecoys) getExpiredRegistrations() []string {
	r.m.RLock()
	defer r.m.RUnlock()

	var expiredRegTimeoutIndices = []string{}

	for idx, regTimeout := range r.decoysTimeouts {
		if regTimeout.status == regStatusUnused && time.Since(regTimeout.registrationTime) > r.timeoutUnused {
			// if a registration has not senewTimeouten a valid connection in within the
			// timeout we remove it from tracking as we do not expect to see a
			// valid connection and no longer need it. Clients should retry with
			// a new registration if connection has failed for this duration.
			expiredRegTimeoutIndices = append(expiredRegTimeoutIndices, idx)
		} else if time.Since(regTimeout.registrationTime) > r.timeoutActive {
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
		Valid:          expiredRegObj.Valid,
		PhantomAddr:    expiredReg.decoy,
		PhantomDstPort: uint(expiredRegObj.PhantomPort),
		Reg2expire:     int64(time.Since(expiredReg.registrationTime) / time.Millisecond),
		RegCount:       expiredRegObj.regCount,

		ASN:         expiredRegObj.regASN,
		CC:          expiredRegObj.regCC,
		Transport:   expiredRegObj.Transport.String(),
		Registrar:   expiredRegObj.RegistrationSource.String(),
		V6:          expiredRegObj.PhantomIp.To4() == nil,
		TunnelCount: uint(expiredRegObj.tunnelCount),
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
//
// returns the number of expired registrations total and the number marked valid
func (r *RegisteredDecoys) removeOldRegistrations(logger *log.Logger) (int, int) {
	var expiredRegTimeoutIndices = r.getExpiredRegistrations()

	logger.Debugf("cleansing registrations - registrations: %d, timeouts: %d, expired: %d",
		r.TotalRegistrations(), len(r.decoysTimeouts), len(expiredRegTimeoutIndices))

	expiredValid := 0
	for _, idx := range expiredRegTimeoutIndices {

		stats := r.removeRegistration(idx)
		if stats != nil {
			if stats.Valid {
				expiredValid++
			}
			statsStr, _ := json.Marshal(stats)
			logger.Debugf("expired reg %s", statsStr)
		}
	}

	return len(expiredRegTimeoutIndices), expiredValid
}

// **NOTE**: If you mess with this function make sure the
// session tracking tests on the detector side do what you expect
// them to do. (conjure/src/session.rs)
func sendToDetector(reg *DecoyRegistration, duration uint64, op pb.StationOperations) {
	client := getRedisClient()
	if client == nil {
		fmt.Printf("couldn't connect to redis")
		return
	}

	src := reg.registrationAddr.String()
	phantom := reg.PhantomIp.String()
	// protocol := reg.GetProto()
	srcPort := uint32(reg.GetSrcPort())
	dstPort := uint32(reg.GetDstPort())
	msg := &pb.StationToDetector{
		PhantomIp: &phantom,
		ClientIp:  &src,
		DstPort:   &dstPort,
		SrcPort:   &srcPort,
		Proto:     &reg.PhantomProto,
		TimeoutNs: &duration,
		Operation: &op,
	}

	s2d, err := proto.Marshal(msg)
	if err != nil {
		// throw(fit)
		return
	}

	ctx := context.Background()
	client.Publish(ctx, DETECTOR_REG_CHANNEL, string(s2d))
}

func clearDetector() {
	client := getRedisClient()
	if client == nil {
		fmt.Printf("couldn't connect to redis")
		return
	}

	op := pb.StationOperations_Clear
	msg := &pb.StationToDetector{
		Operation: &op,
	}

	s2d, err := proto.Marshal(msg)
	if err != nil {
		// throw(fit)
		return
	}

	ctx := context.Background()
	client.Publish(ctx, DETECTOR_REG_CHANNEL, string(s2d))
}
