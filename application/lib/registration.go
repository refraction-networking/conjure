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
		DarkDecoy:    darkDecoyAddr,
		Covert:       c2s.GetCovertAddress(),
		Mask:         c2s.GetMaskedDecoyServerName(),
		MasterSecret: conjureKeys.MasterSecret,
		SharedSecret: conjureKeys.MasterSecret,
		Flags:        uint8(flags[0]),
	}

	// log phantom IP, shared secret, ipv6 support
	regManager.Logger.Printf("New Registration: phantom:%s, shared secret:% x, v6support:%t\n",
		darkDecoyAddr, reg.SharedSecret, c2s.GetV6Support(),
	)

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
	MasterSecret []byte
	SharedSecret []byte
	Covert, Mask string
	Flags        uint8
}

// TODO
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
