package lib

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
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
	logger := log.New(os.Stdout, "", log.Lmicroseconds)

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

func (regManager *RegistrationManager) NewRegistration(c2s *pb.ClientToStation, conjureKeys *ConjureSharedKeys, flags [1]byte) (*DecoyRegistration, error) {

	darkDecoyAddr, err := regManager.DDSelector.Select(
		conjureKeys.DarkDecoySeed, uint(c2s.GetDecoyListGeneration()), c2s.GetV6Support())

	if err != nil {
		return nil, fmt.Errorf("Failed to select dark decoy IP address: %v", err)
	}

	reg := DecoyRegistration{
		DarkDecoy: darkDecoyAddr,
		keys:      conjureKeys,
		Covert:    c2s.GetCovertAddress(),
		Mask:      c2s.GetMaskedDecoyServerName(),
		Flags:     uint8(flags[0]),
	}

	return &reg, nil
}

func (regManager *RegistrationManager) AddRegistration(d *DecoyRegistration) {

	registerForDetector(d)

	darkDecoyAddr := d.DarkDecoy.String()
	regManager.registeredDecoys.register(darkDecoyAddr, d)
}

func (regManager *RegistrationManager) CheckRegistration(darkDecoyAddr *net.IP) *DecoyRegistration {
	return regManager.registeredDecoys.checkRegistration(darkDecoyAddr)
}

func (regManager *RegistrationManager) RemoveOldRegistrations() {
	regManager.registeredDecoys.removeOldRegistrations()
}

type DecoyRegistration struct {
	DarkDecoy    *net.IP
	keys         *ConjureSharedKeys
	Covert, Mask string
	Flags        uint8
}

// String -- Print a digest of the important identifying information for this registration.
//[TODO]{priority:soon} Find a way to add the client IP to this logging for now it is logged
// in the detector associating registrant IP with shared secret.
func (reg *DecoyRegistration) String() string {
	reprStr := make([]byte, hex.EncodedLen(len(reg.keys.SharedSecret)))
	hex.Encode(reprStr, reg.keys.SharedSecret)
	digest := fmt.Sprintf("{phantom=%v, covert=%v, mask=%v, flags=0x%02x, Shared Secret:%s}\n",
		reg.DarkDecoy.String(), reg.Covert, reg.Mask, reg.Flags, reprStr)

	return digest
}

func (reg *DecoyRegistration) IDString() string {
	reprStr := make([]byte, hex.EncodedLen(len(reg.keys.SharedSecret[:8])))
	hex.Encode(reprStr, reg.keys.SharedSecret[:8])
	return fmt.Sprintf("%s", reprStr)
}

// PhantomIsLive - Test whether the phantom is live using
// 8 syns which returns syn-acks from 99% of sites within 1 second.
// see  ZMap: Fast Internet-wide Scanning  and Its Security Applications
// https://www.usenix.org/system/files/conference/usenixsecurity13/sec13-paper_durumeric.pdf
func (reg *DecoyRegistration) PhantomIsLive() bool {
	dialError := make(chan error, 8)

	testConnect := func() {
		conn, err := net.Dial("tcp", reg.DarkDecoy.String())
		if err != nil {
			dialError <- err
			return
		}
		conn.Close()
		dialError <- nil
	}

	for i := 0; i < 8; i++ {
		go testConnect()
	}

	time.Sleep(500 * time.Millisecond)
	// The only error that would return before this is a network unreachable error
	select {
	case _ = <-dialError:
		return false
	default:
		return true
	}
}

type RegisteredDecoys struct {
	decoys         map[string]*DecoyRegistration
	decoysTimeouts []struct {
		decoy            string
		registrationTime time.Time
	}
	m sync.RWMutex
}

func NewRegisteredDecoys() *RegisteredDecoys {
	return &RegisteredDecoys{
		decoys: make(map[string]*DecoyRegistration),
	}
}

func (r *RegisteredDecoys) register(darkDecoyAddr string, d *DecoyRegistration) {
	r.m.Lock()
	if d != nil {
		r.decoys[darkDecoyAddr] = d
		r.decoysTimeouts = append(r.decoysTimeouts, struct {
			decoy            string
			registrationTime time.Time
		}{decoy: darkDecoyAddr, registrationTime: time.Now()})
	}
	r.m.Unlock()
}

func (r *RegisteredDecoys) checkRegistration(darkDecoyAddr *net.IP) *DecoyRegistration {
	darkDecoyAddrStatic := darkDecoyAddr.String()
	r.m.RLock()
	d := r.decoys[darkDecoyAddrStatic]
	r.m.RUnlock()
	return d
}

// TODO log registration expiration
func (r *RegisteredDecoys) removeOldRegistrations() {
	const timeout = -time.Minute * 5
	cutoff := time.Now().Add(timeout)
	idx := 0
	r.m.Lock()
	for idx < len(r.decoysTimeouts) {
		if cutoff.After(r.decoysTimeouts[idx].registrationTime) {
			break
		}
		delete(r.decoys, r.decoysTimeouts[idx].decoy)
		idx += 1
	}
	r.decoysTimeouts = r.decoysTimeouts[idx:]
	r.m.Unlock()
}

func registerForDetector(reg *DecoyRegistration) {
	client, err := getRedisClient()
	if err != nil {
		fmt.Printf("couldn't connect to redis")
	} else {
		client.Publish(DETECTOR_REG_CHANNEL, string(reg.DarkDecoy.To4()))
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
