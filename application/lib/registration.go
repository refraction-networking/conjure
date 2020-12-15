package lib

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis"
	"github.com/golang/protobuf/proto"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

const DETECTOR_REG_CHANNEL string = "dark_decoy_map"
const AES_GCM_TAG_SIZE = 16

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

type RegistrationManager struct {
	registeredDecoys *RegisteredDecoys
	Logger           *log.Logger
	PhantomSelector  *PhantomIPSelector
}

func NewRegistrationManager() *RegistrationManager {
	logger := log.New(os.Stdout, "[REG] ", log.Ldate|log.Lmicroseconds)

	p, err := NewPhantomIPSelector()
	if err != nil {
		// fmt.Errorf("failed to create the PhantomIPSelector object: %v", err)
		return nil
	}
	return &RegistrationManager{
		Logger:           logger,
		registeredDecoys: NewRegisteredDecoys(),
		PhantomSelector:  p,
	}
}

func (regManager *RegistrationManager) AddTransport(index pb.TransportType, t Transport) {
	regManager.registeredDecoys.m.Lock()
	defer regManager.registeredDecoys.m.Unlock()

	regManager.registeredDecoys.transports[index] = t
}

// Returns a map of the wrapping transport types to their transports. This return value
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

func (regManager *RegistrationManager) NewRegistration(c2s *pb.ClientToStation, conjureKeys *ConjureSharedKeys, includeV6 bool, registrationSource *pb.RegistrationSource) (*DecoyRegistration, error) {

	phantomAddr, err := regManager.PhantomSelector.Select(
		conjureKeys.DarkDecoySeed, uint(c2s.GetDecoyListGeneration()), includeV6)

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

func (regManager *RegistrationManager) AddRegistration(d *DecoyRegistration) {

	darkDecoyAddr := d.DarkDecoy.String()
	err := regManager.registeredDecoys.register(darkDecoyAddr, d)
	if err != nil {
		regManager.Logger.Printf("Error registering decoy: %s", err)
	}
}

func (regManager *RegistrationManager) GetRegistrations(darkDecoyAddr net.IP) map[string]*DecoyRegistration {
	return regManager.registeredDecoys.GetRegistrations(darkDecoyAddr)
}

func (regManager *RegistrationManager) CountRegistrations(darkDecoyAddr net.IP) int {
	return regManager.registeredDecoys.countRegistrations(darkDecoyAddr)
}

func (regManager *RegistrationManager) RemoveOldRegistrations() {
	regManager.registeredDecoys.removeOldRegistrations(regManager.Logger)
}

type DecoyRegistration struct {
	DarkDecoy          net.IP
	Keys               *ConjureSharedKeys
	Covert, Mask       string
	Flags              *pb.RegistrationFlags
	Transport          pb.TransportType
	RegistrationTime   time.Time
	RegistrationSource *pb.RegistrationSource
	DecoyListVersion   uint32
	regCount           int32
}

// String -- Print a digest of the important identifying information for this registration.
//[TODO]{priority:soon} Find a way to add the client IP to this logging for now it is logged
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
		Covert:           reg.Covert,
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
	return fmt.Sprintf("%s", secret[:regIDLen])
}

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
	}
	return protoPayload
}

func (reg *DecoyRegistration) PreScanned() bool {
	if reg == nil || reg.Flags == nil {
		return false
	}
	return reg.Flags.GetPrescanned()
}

// PhantomIsLive - Test whether the phantom is live using
// 8 syns which returns syn-acks from 99% of sites within 1 second.
// see  ZMap: Fast Internet-wide Scanning  and Its Security Applications
// https://www.usenix.org/system/files/conference/usenixsecurity13/sec13-paper_durumeric.pdf
//
// return:	bool	true  - host is live
// 					false - host is not life
//			error	reason decision was made
func (reg *DecoyRegistration) PhantomIsLive() (bool, error) {
	return phantomIsLive(net.JoinHostPort(reg.DarkDecoy.String(), "443"))
}

func phantomIsLive(address string) (bool, error) {
	width := 8
	dialError := make(chan error, width)

	testConnect := func() {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			dialError <- err
			return
		}
		conn.Close()
		dialError <- nil
	}

	for i := 0; i < width; i++ {
		go testConnect()
	}

	timeout := 750 * time.Millisecond

	time.Sleep(timeout)

	// If any return errors or connect then return nil before deadline it is live
	select {
	case err := <-dialError:
		// fmt.Printf("Received: %v\n", err)
		if err != nil {
			return true, err
		}
		return true, fmt.Errorf("Phantom picked up the connection")
	default:
		return false, fmt.Errorf("Reached statistical timeout %v", timeout)
	}
}

type DecoyTimeout struct {
	decoy            string
	identifier       string
	registrationTime time.Time
	regID            string
}

type RegisteredDecoys struct {
	// decoys will be a map from decoy_ip to a:
	// map from "registration identifier" to registration.
	// This is one component of what allows a transport to
	// identify a registration; its meaning will differ
	// between transports.
	decoys map[string]map[string]*DecoyRegistration

	transports map[pb.TransportType]Transport

	decoysTimeouts []DecoyTimeout
	m              sync.RWMutex
}

func NewRegisteredDecoys() *RegisteredDecoys {
	return &RegisteredDecoys{
		decoys:     make(map[string]map[string]*DecoyRegistration),
		transports: make(map[pb.TransportType]Transport),
	}
}

func (r *RegisteredDecoys) register(darkDecoyAddr string, d *DecoyRegistration) error {

	r.m.Lock()
	defer r.m.Unlock()

	t, ok := r.transports[d.Transport]
	if !ok {
		return fmt.Errorf("unknown transport %d", d.Transport)
	}

	identifier := t.GetIdentifier(d)

	_, exists := r.decoys[darkDecoyAddr]
	if exists == false {
		r.decoys[darkDecoyAddr] = map[string]*DecoyRegistration{}
	}

	reg, exists := r.decoys[darkDecoyAddr][identifier]
	if exists == false {
		// New Registration not known to the Manager
		r.decoys[darkDecoyAddr][identifier] = d

		r.decoysTimeouts = append(r.decoysTimeouts,
			DecoyTimeout{
				decoy:            darkDecoyAddr,
				identifier:       identifier,
				registrationTime: time.Now(),
				regID:            d.IDString(),
			})

		//[TODO]{priority:5} track what registration decoys are seen for a given session
		d.regCount = 1
		registerForDetector(d)
	} else {
		reg.regCount++
	}

	return nil
}

func (r *RegisteredDecoys) GetRegistrations(darkDecoyAddr net.IP) map[string]*DecoyRegistration {
	darkDecoyAddrStatic := darkDecoyAddr.String()
	r.m.RLock()
	defer r.m.RUnlock()

	original := r.decoys[darkDecoyAddrStatic]

	regs := make(map[string]*DecoyRegistration)
	for k, v := range original {
		regs[k] = v
	}

	return regs
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

type regExpireLogMsg struct {
	DecoyAddr  string
	Reg2expire int64
	RegID      string
	RegCount   int32
}

func (r *RegisteredDecoys) removeOldRegistrations(logger *log.Logger) {
	const timeout = -time.Minute * 5
	cutoff := time.Now().Add(timeout)
	idx := 0
	r.m.Lock()
	defer r.m.Unlock()

	logger.Printf("cleansing registrations")
	for idx := 0; idx < len(r.decoysTimeouts); idx++ {
		if cutoff.After(r.decoysTimeouts[idx].registrationTime) {
			break
		}
		expiredReg := r.decoysTimeouts[idx]
		expiredRegObj, ok := r.decoys[expiredReg.decoy][expiredReg.identifier]
		if !ok {
			continue
		}
		delete(r.decoys[expiredReg.decoy], expiredReg.identifier)
		stats := regExpireLogMsg{
			DecoyAddr:  expiredReg.decoy,
			Reg2expire: int64(time.Since(expiredReg.registrationTime) / time.Millisecond),
			RegID:      expiredReg.regID,
			RegCount:   expiredRegObj.regCount,
		}
		statsStr, _ := json.Marshal(stats)
		logger.Printf("expired registration %s", statsStr)
	}
	r.decoysTimeouts = r.decoysTimeouts[idx:]
}

func registerForDetector(reg *DecoyRegistration) {
	client, err := getRedisClient()
	if err != nil {
		fmt.Printf("couldn't connect to redis")
	} else {
		if reg.DarkDecoy.To4() != nil {
			client.Publish(DETECTOR_REG_CHANNEL, string(reg.DarkDecoy.To4()))
		} else {
			client.Publish(DETECTOR_REG_CHANNEL, string(reg.DarkDecoy.To16()))
		}
		client.Close()
	}
}

func getRedisClient() (*redis.Client, error) {
	var client *redis.Client
	client = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
		PoolSize: 10,
	})

	_, err := client.Ping().Result()
	if err != nil {
		return client, err
	}

	return client, err
}
