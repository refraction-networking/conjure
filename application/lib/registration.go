package lib

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/go-redis/redis"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

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

func (regManager *RegistrationManager) NewRegistration(c2s *pb.ClientToStation, conjureKeys *conjureSharedKeys, flags [1]byte) (*DecoyRegistration, error) {

	darkDecoyAddr, err := regManager.DDSelector.Select(
		conjureKeys.DarkDecoySeed, uint(c2s.GetDecoyListGeneration()), c2s.GetV6Support())

	if err != nil {
		return nil, fmt.Errorf("Failed to select dark decoy IP address: %v", err)
	}

	reg := DecoyRegistration{
		DarkDecoy:    darkDecoyAddr,
		Covert:       c2s.GetCovertAddress(),
		Mask:         c2s.GetMaskedDecoyServerName(),
		MasterSecret: conjureKeys.MasterSecret,
		Flags:        uint8(flags[0]),
	}
	return &reg, nil
}
func (regManager *RegistrationManager) AddRegistration(d *DecoyRegistration) {

	registerForDetector(&DecoyRegistration)

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
	MasterSecret []byte
	Covert, Mask string
	Flags        uint8
}

func (reg *DecoyRegistration) PhantomIsLive() bool {
	return true
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

	client := getRedisClient()

	result := client.Publish(DETECTOR_REG_CHANNEL, message)
}

func getRedisClient() *redis.Client {
	var client *redis.Client
	client = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       0,
		PoolSize: 10,
	})
	return client
}
