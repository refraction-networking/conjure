package lib

import (
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
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

const DETECTOR_REG_CHANNEL string = "dark_decoy_map"

type RegistrationManager struct {
	registeredDecoys *RegisteredDecoys
	Logger           *log.Logger
	DDSelector       *DDIpSelector
}

func NewRegistrationManager() *RegistrationManager {
	logger := log.New(os.Stdout, "[REG] ", log.Ldate|log.Lmicroseconds)

	d, err := NewDDIpSelector()
	if err != nil {
		fmt.Errorf("Failed to create the DDIpSelector Object: %v\n", err)
		return nil
	}
	return &RegistrationManager{
		Logger:           logger,
		registeredDecoys: NewRegisteredDecoys(),
		DDSelector:       d,
	}
}

func (regManager *RegistrationManager) NewRegistration(c2s *pb.ClientToStation, conjureKeys *ConjureSharedKeys, flags [1]byte, includeV6 bool) (*DecoyRegistration, error) {

	phantomAddr, err := regManager.DDSelector.Select(
		conjureKeys.DarkDecoySeed, uint(c2s.GetDecoyListGeneration()), includeV6)

	if err != nil {
		return nil, fmt.Errorf("Failed to select phantom IP address: %v", err)
	}

	reg := DecoyRegistration{
		DarkDecoy:        phantomAddr,
		keys:             conjureKeys,
		Covert:           c2s.GetCovertAddress(),
		Mask:             c2s.GetMaskedDecoyServerName(),
		Flags:            uint8(flags[0]),
		Transport:        uint(c2s.GetTransport()), // hack
		decoyListVersion: c2s.GetDecoyListGeneration(),
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

func (regManager *RegistrationManager) CheckRegistration(darkDecoyAddr *net.IP, hmacId []byte) *DecoyRegistration {
	return regManager.registeredDecoys.checkRegistration(darkDecoyAddr, hmacId, regManager.Logger)
}

func (regManager *RegistrationManager) CountRegistrations(darkDecoyAddr *net.IP) int {
	return regManager.registeredDecoys.countRegistrations(darkDecoyAddr)
}

func (regManager *RegistrationManager) RemoveOldRegistrations() {
	regManager.registeredDecoys.removeOldRegistrations(regManager.Logger)
}

// Note: These must match the order in the client tapdance/conjure.go transports
// and the C2S protobuf
const (
	NullTransport uint = iota
	MinTransport
	Obfs4Transport
)

type DecoyRegistration struct {
	DarkDecoy        *net.IP
	keys             *ConjureSharedKeys
	Covert, Mask     string
	Flags            uint8
	Transport        uint
	registrationTime time.Time
	decoyListVersion uint32
}

// String -- Print a digest of the important identifying information for this registration.
//[TODO]{priority:soon} Find a way to add the client IP to this logging for now it is logged
// in the detector associating registrant IP with shared secret.
func (reg *DecoyRegistration) String() string {
	if reg == nil {
		return fmt.Sprintf("%v", reg.String())
	}

	stats := struct {
		phantom          string
		sharedSecret     string
		Covert, Mask     string
		Flags            uint8
		Transport        uint
		regTime          time.Time
		decoyListVersion uint32
	}{
		phantom:          reg.DarkDecoy.String(),
		sharedSecret:     hex.EncodeToString(reg.keys.SharedSecret),
		Covert:           reg.Covert,
		Mask:             reg.Mask,
		Flags:            reg.Flags,
		Transport:        reg.Transport,
		regTime:          reg.registrationTime,
		decoyListVersion: reg.decoyListVersion,
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

	if reg == nil || reg.keys == nil {

		return nilID
	}

	secret := make([]byte, hex.EncodedLen(len(reg.keys.SharedSecret)))
	n := hex.Encode(secret, reg.keys.SharedSecret)
	if n < 16 {
		return nilID
	}
	return fmt.Sprintf("%s", secret[:regIDLen])
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
		return true, nil
	default:
		return false, fmt.Errorf("Reached statistical timeout %v ms", timeout)
	}
}

type DecoyTimeout struct {
	decoy            string
	hmacId           string
	registrationTime time.Time
	regID            string
}

type RegisteredDecoys struct {
	// decoys will be a map from decoy_ip to a:
	//						map from 32-byte hmac identifier to decoy registration
	// TODO: allow this to support things like obfs4 on one IP and min transport on another, etc
	decoys map[string]map[string]*DecoyRegistration
	//_null_decoys   map[string]*DecoyRegistration
	decoysTimeouts []DecoyTimeout
	m              sync.RWMutex
}

func NewRegisteredDecoys() *RegisteredDecoys {
	return &RegisteredDecoys{
		decoys: make(map[string]map[string]*DecoyRegistration),
	}
}

func (r *RegisteredDecoys) register(darkDecoyAddr string, d *DecoyRegistration) error {

	r.m.Lock()
	defer r.m.Unlock()

	if d != nil {
		// Update decoy registration time
		d.registrationTime = time.Now()
		switch d.Transport {
		case MinTransport:
			hmacId := string(d.keys.conjureHMAC("MinTrasportHMACString"))

			_, exists := r.decoys[darkDecoyAddr]
			if exists == false {
				r.decoys[darkDecoyAddr] = map[string]*DecoyRegistration{}
			}
			reg, exists := r.decoys[darkDecoyAddr][hmacId]
			if reg == nil {
				// New Registration not known to the Manager
				r.decoys[darkDecoyAddr][hmacId] = d

				r.decoysTimeouts = append(r.decoysTimeouts,
					DecoyTimeout{
						decoy:            darkDecoyAddr,
						hmacId:           hmacId,
						registrationTime: time.Now(),
						regID:            d.IDString(),
					})

				//[TODO]{priority:5} track what registration decoys are seen for a given session

				registerForDetector(d)

			}
		case Obfs4Transport:
			fallthrough
		case NullTransport:
			fallthrough
		default:
			return fmt.Errorf("Unsupported transport %d for decoy %s", d.Transport, darkDecoyAddr)
		}
	}
	return nil
}

func (r *RegisteredDecoys) checkRegistration(darkDecoyAddr *net.IP, hmacId []byte, logger *log.Logger) *DecoyRegistration {
	darkDecoyAddrStatic := darkDecoyAddr.String()
	r.m.RLock()
	defer r.m.RUnlock()

	regs, exists := r.decoys[darkDecoyAddrStatic]
	if !exists {
		return nil
	}
	d := regs[string(hmacId)]
	// Calculate time delta between registration and connection
	if d == nil {
		return nil
	}
	reg_delta := int64(time.Since(d.registrationTime) / time.Millisecond)
	logger.Printf("connection to registration %s, %v, %s took %v", d.IDString(), darkDecoyAddr, hex.EncodeToString(hmacId), reg_delta)
	return d
}

func (r *RegisteredDecoys) countRegistrations(darkDecoyAddr *net.IP) int {
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
	decoyAddr  string
	reg2Conn   int64
	reg2expire int64
	regID      string
}

func (r *RegisteredDecoys) removeOldRegistrations(logger *log.Logger) {
	const timeout = -time.Minute * 5
	cutoff := time.Now().Add(timeout)
	idx := 0
	r.m.Lock()
	defer r.m.Unlock()

	logger.Printf("cleansing registrations")
	for idx < len(r.decoysTimeouts) {
		if cutoff.After(r.decoysTimeouts[idx].registrationTime) {
			break
		}
		expiredReg := r.decoysTimeouts[idx]
		delete(r.decoys[expiredReg.decoy], expiredReg.hmacId)
		stats := regExpireLogMsg{
			decoyAddr:  expiredReg.decoy,
			reg2expire: int64(time.Since(expiredReg.registrationTime) / time.Millisecond),
			regID:      expiredReg.regID,
		}
		statsStr, _ := json.Marshal(stats)
		logger.Printf("expired registration %s", statsStr)
		idx++
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
