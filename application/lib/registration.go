package lib

import (
	"log"
	"net"
	"os"
	"sync"
	"time"
)

type RegistrationManager struct {
	registeredDecoys *RegisteredDecoys
	Logger           *log.Logger
}

func NewRegistrationManager() *RegistrationManager {
	logger := log.New(os.Stdout, "", log.Lmicroseconds)

	return &RegistrationManager{
		Logger:           logger,
		registeredDecoys: NewRegisteredDecoys(),
	}
}

func (regManager *RegistrationManager) AddRegistration(darkDecoyAddr [16]byte, d *DecoyRegistration) {
	regManager.registeredDecoys.register(darkDecoyAddr, d)
}

func (regManager *RegistrationManager) CheckRegistration(darkDecoyAddr net.IP) *DecoyRegistration {
	return regManager.registeredDecoys.checkRegistration(darkDecoyAddr)
}

func (regManager *RegistrationManager) RemoveOldRegistrations() {
	regManager.registeredDecoys.removeOldRegistrations()
}

type DecoyRegistration struct {
	MasterSecret [48]byte
	Covert, Mask string
	Flags        uint8
}

type RegisteredDecoys struct {
	decoys         map[[16]byte]*DecoyRegistration
	decoysTimeouts []struct {
		decoy            [16]byte
		registrationTime time.Time
	}
	m sync.RWMutex
}

func NewRegisteredDecoys() *RegisteredDecoys {
	return &RegisteredDecoys{
		decoys: make(map[[16]byte]*DecoyRegistration),
	}
}

func (r *RegisteredDecoys) register(darkDecoyAddr [16]byte, d *DecoyRegistration) {
	r.m.Lock()
	if d != nil {
		r.decoys[darkDecoyAddr] = d
		r.decoysTimeouts = append(r.decoysTimeouts, struct {
			decoy            [16]byte
			registrationTime time.Time
		}{decoy: darkDecoyAddr, registrationTime: time.Now()})
	}
	r.m.Unlock()
}

func (r *RegisteredDecoys) checkRegistration(darkDecoyAddr net.IP) *DecoyRegistration {
	var darkDecoyAddrStatic [16]byte
	copy(darkDecoyAddrStatic[:], darkDecoyAddr)
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
