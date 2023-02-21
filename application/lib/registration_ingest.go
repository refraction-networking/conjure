package lib

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	pb "github.com/refraction-networking/gotapdance/protobuf"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/refraction-networking/conjure/application/liveness"
	"github.com/refraction-networking/conjure/application/log"
)

const (
	defaultWorkerCount = 300
	// Job buffer 1/10th the number of workers to make sure it doesn't back up,
	// invalidating registrations.
	jobBufferDivisor = 10
)

const (
	// Earliest client library version ID that supports destination port randomization
	randomizeDstPortMinVersion uint = 3
)

// HandleRegUpdates is responsible for launching and managing registration
// ingest from the perspective of the RegistrationManager. The keys to success
// in this job are:
//  1. Launch a fixed number of workers to process registration messages
//  2. read from the registration channel as though it is blocking
//  3. write jobs to works non-blocking. any time a registration is received,
//     but a worker is not available the registration is simple dropped and
//     counted for metrics
//  4. Keep a shallow buffer to drop as few registrations as possible. The
//     buffer must be shallow so that registrations that end up buffered are
//     still relevant when they make it out of the buffer.
func (rm *RegistrationManager) HandleRegUpdates(ctx context.Context, regChan <-chan interface{}, parentWG *sync.WaitGroup) {
	defer parentWG.Done()
	logger := rm.Logger
	workers := defaultWorkerCount
	if rm.IngestWorkerCount != 0 {
		workers = rm.IngestWorkerCount
	}

	wg := new(sync.WaitGroup)

	// Add a shallow buffer for incoming registrations
	shallowBuffer := make(chan interface{}, workers/jobBufferDivisor)
	defer close(shallowBuffer)

	// Add to registration manager so that we cann access it for stats printing.
	rm.ingestChan = shallowBuffer

	// launch workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go rm.startIngestThread(ctx, shallowBuffer, wg)
	}

	// distribute messages to workers. When workers are unavailable messages are
	// added into channel buffer until full, then dropped.
distrLoop:
	for msg := range regChan {
		rm.addIngestMessage()
		select {
		case <-ctx.Done():
			logger.Infof("closing all ingest threads")
			break distrLoop
		case shallowBuffer <- msg:
		default:
			logger.Tracef("dropping registration")
			rm.addDroppedMessage()
		}
	}

	wg.Wait()
}

// startIngestThread begins one worked that draws from the provided channel
// where unparsed registration messages are passed to be handled and ingested.
// The worker is responsible for parsing the registration, ingesting it into
// the registration manager and moving on to the next message.
func (rm *RegistrationManager) startIngestThread(ctx context.Context, regChan <-chan interface{}, wg *sync.WaitGroup) {
	defer wg.Done()
	logger := rm.Logger

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-regChan:
			newRegs, err := rm.parseRegMessage(msg.([]byte))
			if err != nil {
				logger.Errorf("Encountered err when creating Reg: %v\n", err)
				continue
			}
			if len(newRegs) == 0 {
				// no new registration
				continue
			}

			// Handle multiple -- handleRegMessage parses the registration and
			// returns separate DecoyRegistration objects for v4 and v6
			for _, reg := range newRegs {

				if reg == nil {
					continue
				}

				rm.ingestRegistration(reg)
			}
		}
	}
}

func (rm *RegistrationManager) ingestRegistration(reg *DecoyRegistration) {
	logger := rm.Logger

	if ok, err := rm.ValidateRegistration(reg); !ok || err != nil {
		if err == errBlocklistedPhantom {
			rm.AddBlocklistedPhantomReg()
		} else {
			logger.Errorln("error tracking registration: ", err)
			Stat().AddErrReg()
		}
		return
	}

	if rm.RegistrationExists(reg) {
		// log phantom IP, shared secret, ipv6 support
		logger.Debugf("Duplicate registration: %v %s\n", reg.IDString(), reg.RegistrationSource)
		Stat().AddDupReg()
		rm.AddDupReg()

		// Track the received registration, if it is already tracked
		// it will just update the record
		err := rm.TrackRegistration(reg)
		if err != nil {
			logger.Errorln("error tracking registration: ", err)
			Stat().AddErrReg()
			rm.AddErrReg()
		}
		return
	}

	// log phantom IP, shared secret, ipv6 support
	logger.Debugf("New registration: %s %v\n", reg.IDString(), reg.String())

	// Track the received registration
	err := rm.TrackRegistration(reg)
	if err != nil {
		logger.Errorln("error tracking registration: ", err)
		Stat().AddErrReg()
		rm.AddErrReg()

	}

	// If registration is trying to connect to a covert address that
	// is blocklisted consider registration INVALID and continue
	covert, lookup := rm.ParseOrResolveBlocklisted(reg.Covert)
	if lookup {
		rm.addDNSResolution()
	}
	if covert == "" {
		// We log client IPs for clients attempting to connect to
		// blocklisted covert addresses.
		logger.Infof("Dropping reg, malformed or blocklisted covert: %v, %s -> %s", reg.IDString(), reg.GetRegistrationAddress(), reg.Covert)
		Stat().AddErrReg()
		rm.AddErrReg()
		return
	}

	// Overwrite provided covert with resolved address. This kind of
	// sucks because net.Dial can try multiple addresses for domain
	// names w/ multiple records when resolved and we lock to one
	// address. However, this step is required to prevent SSRF via
	// DNS rebinding. Clients generally shouldn't be providing
	// hostnames as coverts anyways.
	reg.Covert = covert

	// Perform liveness test IFF not done by other station or v6 (v6 should
	// never be live)
	if !reg.PreScanned() && reg.PhantomIp.To4() != nil {
		// New registration received over channel that requires liveness scan for the phantom
		live, response := rm.PhantomIsLive(reg.PhantomIp.String(), reg.PhantomPort)

		// TODO JMWAMPLE REMOVE
		if live {
			logger.Warnf("Dropping registration %v -- live phantom: %v\n", reg.IDString(), response)
			if errors.Is(response, liveness.ErrCachedPhantom) {
				Stat().AddLivenessCached()
			}
			Stat().AddLivenessFail()
			return
		}
		Stat().AddLivenessPass()
	}

	if *reg.RegistrationSource == pb.RegistrationSource_Detector {
		if rm.EnableShareOverAPI {
			// Registration received from decoy-registrar, share over API if enabled.
			go tryShareRegistrationOverAPI(reg, rm.PreshareEndpoint, rm.Logger)
		}

		if rm.IsBlocklistedPhantom(reg.PhantomIp) {
			// Note: Phantom blocklist is applied for registrations using the
			// decoy registrar at this stage because the phantom may only be
			// blocked on this station. We may want other stations to be
			// informed about the registration, but prevent this station
			// specifically from handling / interfering in any subsequent
			// connection. See PR #75
			logger.Warnf("ignoring registration with blocklisted phantom: %s %v", reg.IDString(), reg.PhantomIp)
			Stat().AddErrReg()
			rm.AddBlocklistedPhantomReg()
			return
		}

	}
	// validate the registration
	rm.AddRegistration(reg)
	logger.Debugf("Adding registration %v\n", reg.IDString())
	Stat().AddReg(reg.DecoyListVersion, reg.RegistrationSource)
	rm.AddRegStats(reg)
}

func tryShareRegistrationOverAPI(reg *DecoyRegistration, apiEndpoint string, logger *log.Logger) {
	c2a := reg.GenerateC2SWrapper()

	payload, err := proto.Marshal(c2a)
	if err != nil {
		logger.Errorf("%v failed to marshal C2SWrapper payload: %v", reg.IDString(), err)
		return
	}

	err = executeHTTPRequest(reg, payload, apiEndpoint)
	if err != nil {
		logger.Errorf("%v failed to share Registration over API: %v", reg.IDString(), err)
	}
}

func executeHTTPRequest(reg *DecoyRegistration, payload []byte, apiEndpoint string) error {
	resp, err := http.Post(apiEndpoint, "", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("non-success response code %d on %s", resp.StatusCode, apiEndpoint)
	}

	return nil
}

// parseRegMessage ingests messages from zmq and parses them into registration
// structs for the registration manager to process. **NOTE** : Avoid ALL
// blocking calls (i.e. things that require a lock on the registration tracking
// structs) in this method because it will block and prevent the station from
// ingesting new registrations. **NOTE2**: If the registration address is IPv4
// we will create registrations for both IPv4 decoy and IPv6 decoy. However, If
// the client Address from registrations is IPv6 we will only create an ipv6
// registration because
//  1. we have no client address to match on for ipv4
//  2. the client _should_ support ipv6
func (rm *RegistrationManager) parseRegMessage(msg []byte) ([]*DecoyRegistration, error) {
	logger := rm.Logger

	parsed := &pb.C2SWrapper{}
	err := proto.Unmarshal(msg, parsed)
	if err != nil {
		logger.Errorf("Failed to unmarshall ClientToStation: %v", err)
		return nil, err
	}

	// if either address is not provided (reg came over api / client ip
	// logging disabled) fill with zeros to avoid nil dereference.
	if parsed.GetRegistrationAddress() == nil {
		parsed.RegistrationAddress = make([]byte, 16)
	}
	if parsed.GetDecoyAddress() == nil {
		parsed.DecoyAddress = make([]byte, 16)
	}

	// If client IP logging is disabled DO NOT parse source IP.
	var sourceAddr, phantomAddr net.IP
	sourceAddr = net.IP(parsed.GetRegistrationAddress())
	phantomAddr = net.IP(parsed.GetDecoyAddress())

	// Register one or both of v4 and v6 based on support specified by the client
	var newRegs []*DecoyRegistration

	// if the clients address is ipv6 skip creating an ipv4 registration.
	if parsed.GetRegistrationPayload().GetV4Support() && rm.EnableIPv4 && sourceAddr.To4() != nil {
		reg, err := rm.NewRegistrationC2SWrapper(parsed, false)
		if err != nil {
			logger.Errorf("Failed to create registration from v4 C2S: %v", err)
			return nil, err
		}

		// Received new registration, parse it and return
		newRegs = append(newRegs, reg)
	}

	if parsed.GetRegistrationPayload().GetV6Support() && rm.EnableIPv6 {
		reg, err := rm.NewRegistrationC2SWrapper(parsed, true)
		if err != nil {
			logger.Errorf("Failed to create registration from v6 C2S: %v", err)
			return nil, err
		}
		// add to list of new registrations to be processed.
		newRegs = append(newRegs, reg)
	}

	// log decoy connection and id string if debug logging is enabled.
	if len(newRegs) > 0 {
		logger.Debugf("received registration: '%v' -> '%v' %v %s\n", sourceAddr, phantomAddr, newRegs[0].IDString(), parsed.GetRegistrationSource())
	}
	return newRegs, nil
}

// NewRegistration creates a new registration from details provided. Adds the registration
// to tracking map, But marks it as not valid. This is a utility function, it its not
// used in the ingest pipeline
func (rm *RegistrationManager) NewRegistration(c2s *pb.ClientToStation, conjureKeys *ConjureSharedKeys, includeV6 bool, registrationSource *pb.RegistrationSource) (*DecoyRegistration, error) {
	gen := uint(c2s.GetDecoyListGeneration())
	clientLibVer := uint(c2s.GetClientLibVersion())
	phantomAddr, err := rm.PhantomSelector.Select(
		conjureKeys.ConjureSeed, gen, clientLibVer, includeV6)

	if err != nil {
		return nil, fmt.Errorf("failed phantom select: gen %d libv %d v6 %t err: %v",
			gen,
			clientLibVer,
			includeV6,
			err)
	}

	transportParams, err := rm.getTransportParams(c2s.GetTransport(), c2s.GetTransportParams(), clientLibVer)
	if err != nil {
		return nil, fmt.Errorf("error handling transport params: %s", err)
	}

	phantomPort, err := rm.getPhantomDstPort(c2s.GetTransport(), transportParams, conjureKeys.ConjureSeed, clientLibVer)
	if err != nil {
		return nil, fmt.Errorf("error selecting phantom dst port: %s", err)
	}

	phantomProto, err := rm.getTransportProto(c2s.GetTransport(), transportParams, clientLibVer)
	if err != nil {
		return nil, fmt.Errorf("error determining phantom connection proto: %s", err)
	}

	reg := DecoyRegistration{
		DecoyListVersion: c2s.GetDecoyListGeneration(),
		Keys:             conjureKeys,
		Covert:           c2s.GetCovertAddress(),
		Transport:        c2s.GetTransport(),
		TransportParams:  transportParams,
		Flags:            c2s.Flags,

		PhantomIp:    phantomAddr,
		PhantomPort:  phantomPort,
		PhantomProto: phantomProto,

		Mask: c2s.GetMaskedDecoyServerName(),

		RegistrationSource: registrationSource,
		RegistrationTime:   time.Now(),
		regCount:           0,
		tunnelCount:        0,
	}

	return &reg, nil
}

// NewRegistrationC2SWrapper creates a new registration from details provided. Adds the registration
// to tracking map, But marks it as not valid.
func (rm *RegistrationManager) NewRegistrationC2SWrapper(c2sw *pb.C2SWrapper, includeV6 bool) (*DecoyRegistration, error) {
	c2s := c2sw.GetRegistrationPayload()

	// Generate keys from shared secret using HKDF
	conjureKeys, err := GenSharedKeys(c2sw.GetSharedSecret(), c2s.GetTransport())
	if err != nil {
		return nil, fmt.Errorf("failed to generate keys: %v", err)
	}

	regSrc := c2sw.GetRegistrationSource()

	reg, err := rm.NewRegistration(c2s, &conjureKeys, includeV6, &regSrc)
	if err != nil || reg == nil {
		return nil, fmt.Errorf("failed to build registration: %s", err)
	}

	clientAddr := net.IP(c2sw.GetRegistrationAddress())

	if reg.PhantomIp.To4() != nil && clientAddr.To4() == nil {
		// This can happen if the client chooses from a set that contains no
		// ipv6 options even if include ipv6 is enabled they will get ipv4.
		return nil, fmt.Errorf("failed because IPv6 client chose IPv4 phantom")
	}

	reg.registrationAddr = clientAddr
	reg.regCC, err = rm.GeoIP.CC(reg.registrationAddr)
	if err != nil {
		return nil, fmt.Errorf("failed geoip cc lookup: %w", err)
	}
	reg.regASN, err = rm.GeoIP.ASN(reg.registrationAddr)
	if err != nil {
		return nil, fmt.Errorf("failed geoip asn lookup: %w", err)
	}

	return reg, nil
}

func (rm *RegistrationManager) getTransportParams(t pb.TransportType, data *anypb.Any, libVer uint) (any, error) {
	var transport, ok = rm.registeredDecoys.transports[t]
	if !ok {
		return 0, fmt.Errorf("unknown transport")
	}

	return transport.ParseParams(libVer, data)
}

// getTransportProto returns the IP next layer protocol that this session will use to connect.
// For transport this could potentially depend on library version, params, etc.
func (rm *RegistrationManager) getTransportProto(t pb.TransportType, params any, libVer uint) (pb.IPProto, error) {
	var transport, ok = rm.registeredDecoys.transports[t]
	if !ok {
		return 0, fmt.Errorf("unknown transport")
	}

	return transport.GetProto(), nil
}

// getPhantomDstPort returns the proper phantom port based on registration type, transport
// parameters provided by the client and session details (also provided by the client).
func (rm *RegistrationManager) getPhantomDstPort(t pb.TransportType, params any, seed []byte, libVer uint) (uint16, error) {
	var transport, ok = rm.registeredDecoys.transports[t]
	if !ok {
		return 0, fmt.Errorf("unknown transport")
	}

	if libVer < randomizeDstPortMinVersion {
		// Before randomizeDstPortMinVersion all transport (min and obfs4) exclusively used 443 as
		// their destination port.
		return 443, nil
	}

	// GetDstPort Given the library version, a seed, and a generic object containing parameters the
	// transport should be able to return the destination port that a clients phantom connection
	// will attempt to reach. The libVersion is provided incase of version dependent changes in the
	// transport selection algorithms themselves.
	return transport.GetDstPort(libVer, seed, params)
}
