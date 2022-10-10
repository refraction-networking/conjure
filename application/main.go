package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	golog "log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"time"

	pb "github.com/refraction-networking/gotapdance/protobuf"
	"google.golang.org/protobuf/proto"

	cj "github.com/refraction-networking/conjure/application/lib"
	lt "github.com/refraction-networking/conjure/application/liveness"
	"github.com/refraction-networking/conjure/application/log"
	"github.com/refraction-networking/conjure/application/transports"
	"github.com/refraction-networking/conjure/application/transports/wrapping/min"
	"github.com/refraction-networking/conjure/application/transports/wrapping/obfs4"
)

func getOriginalDst(fd uintptr) (net.IP, error) {
	const SO_ORIGINAL_DST = 80
	if sockOpt, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, SO_ORIGINAL_DST); err == nil {
		// parse ipv4
		return net.IPv4(sockOpt.Multiaddr[4], sockOpt.Multiaddr[5], sockOpt.Multiaddr[6], sockOpt.Multiaddr[7]), nil
	} else if mtuinfo, err := syscall.GetsockoptIPv6MTUInfo(int(fd), syscall.IPPROTO_IPV6, SO_ORIGINAL_DST); err == nil {
		// parse ipv6
		return net.IP(mtuinfo.Addr.Addr[:]), nil
	} else {
		return nil, err
	}
}

// Handle connection from client
// NOTE: this is called as a goroutine
func handleNewConn(regManager *cj.RegistrationManager, clientConn *net.TCPConn) {
	defer clientConn.Close()
	logger := sharedLogger

	fd, err := clientConn.File()
	if err != nil {
		logger.Errorln("failed to get file descriptor on clientConn:", err)
		return
	}

	// TODO: if NOT mPort 443: just forward things and return
	fdPtr := fd.Fd()
	originalDstIP, err := getOriginalDst(fdPtr)
	if err != nil {
		logger.Errorln("failed to getOriginalDst from fd:", err)
		return
	}

	// We need to set the underlying file descriptor back into
	// non-blocking mode after calling Fd (which puts it into blocking
	// mode), or else deadlines won't work.
	err = syscall.SetNonblock(int(fdPtr), true)
	if err != nil {
		logger.Errorln("failed to set non-blocking mode on fd:", err)
	}
	fd.Close()

	var originalDst, originalSrc string
	if logClientIP {
		originalSrc = clientConn.RemoteAddr().String()
	} else {
		originalSrc = "_"
	}
	originalDst = originalDstIP.String()
	flowDescription := fmt.Sprintf("%s -> %s ", originalSrc, originalDst)
	logger = log.New(os.Stdout, "[CONN] "+flowDescription, golog.Ldate|golog.Lmicroseconds)

	count := regManager.CountRegistrations(originalDstIP)
	logger.Debugf("new connection (%d potential registrations)\n", count)
	cj.Stat().AddConn()

	// Pick random timeout between 10 and 60 seconds, down to millisecond precision
	ms := rand.Int63n(50000) + 10000
	timeout := time.Duration(ms) * time.Millisecond

	// Give the client a deadline to send enough data to identify a transport.
	// This can be reset by transports to give more time for handshakes
	// after a transport is identified.
	deadline := time.Now().Add(timeout)
	err = clientConn.SetDeadline(deadline)
	if err != nil {
		logger.Errorln("error occurred while setting deadline:", err)
	}

	if count < 1 {
		// Here, reading from the connection would be pointless, but
		// since the kernel already ACK'd this connection, we gain no
		// benefit from instantly dropping the connection; the jig is
		// already up. We should keep reading in line with other code paths
		// so the initiator of the connection gains no information
		// about the correctness of their connection.
		//
		// Possible TODO: use NFQUEUE to be able to drop the connection
		// in userspace before the SYN-ACK is sent, increasing probe
		// resistance.
		logger.Debugf("no possible registrations, reading for %v then dropping connection\n", timeout)
		cj.Stat().AddMissedReg()
		cj.Stat().CloseConn()

		// Copy into io.Discard to keep ACKing until the deadline.
		// This should help prevent fingerprinting; if we let the read
		// buffer fill up and stopped ACKing after 8192 + (buffer size)
		// bytes for obfs4, as an example, that would be quite clear.
		_, err = io.Copy(io.Discard, clientConn)
		if err != nil {
			logger.Errorln("error occurred discarding data:", err)
		}

		return
	}

	var buf [4096]byte
	received := bytes.Buffer{}
	possibleTransports := regManager.GetWrappingTransports()

	var reg *cj.DecoyRegistration
	var wrapped net.Conn

readLoop:
	for {
		if len(possibleTransports) < 1 {
			logger.Warnf("ran out of possible transports, reading for %v then giving up\n", time.Until(deadline))
			cj.Stat().ConnErr()
			_, err = io.Copy(io.Discard, clientConn)
			if err != nil {
				logger.Errorln("error occurred discarding data:", err)
			}
			return
		}

		n, err := clientConn.Read(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				continue
			} else if errors.Is(err, syscall.ECONNRESET) {
				logger.Errorf("got error while reading from connection, giving up after %d bytes: rst\n", received.Len())
			} else if err != nil {
				logger.Errorf("got error while reading from connection, giving up after %d bytes: %v\n", received.Len(), err)
			}
			cj.Stat().ConnErr()
			return
		}
		received.Write(buf[:n])
		logger.Tracef("read %d bytes so far", received.Len())

	transports:
		for i, t := range possibleTransports {
			reg, wrapped, err = t.WrapConnection(&received, clientConn, originalDstIP, regManager)
			if errors.Is(err, transports.ErrTryAgain) {
				continue transports
			} else if errors.Is(err, transports.ErrNotTransport) {
				logger.Tracef("not transport %s, removing from checks\n", t.Name())
				delete(possibleTransports, i)
				continue transports
			} else if err != nil {
				// If we got here, the error might have been produced while attempting
				// to wrap the connection, which means received and the connection
				// may no longer be valid. We should just give up on this connection.
				d := time.Until(deadline)
				logger.Warnf("got unexpected error from transport %s, sleeping %v then giving up: %v\n", t.Name(), d, err)
				cj.Stat().ConnErr()
				time.Sleep(d)
				return
			}

			// We found our transport! First order of business: disable deadline
			err = wrapped.SetDeadline(time.Time{})
			if err != nil {
				logger.Errorln("error occurred while setting deadline:", err)
			}

			logger.SetPrefix(fmt.Sprintf("[%s] %s ", t.LogPrefix(), reg.IDString()))
			logger.Debugf("registration found {reg_id: %s, phantom: %s, transport: %s}\n", reg.IDString(), originalDstIP, t.Name())
			break readLoop
		}
	}

	cj.Proxy(reg, wrapped, logger)
	cj.Stat().CloseConn()
}

func handleRegUpdates(regManager *cj.RegistrationManager, regChan <-chan interface{}, conf *cj.Config) {
	logger := regManager.Logger
	for msg := range regChan {
		newRegs, err := handleRegMessage(msg.([]byte), regManager, conf)
		if err != nil {
			logger.Errorf("Encountered err when creating Reg: %v\n", err)
			continue
		}
		if len(newRegs) == 0 {
			// no new registration
			continue
		}

		// Handle multiple as receive_zmq_messages returns separate
		// registrations for v4 and v6
		for _, reg := range newRegs {

			if reg == nil {
				continue
			}

			go func(reg *cj.DecoyRegistration) {

				if regManager.RegistrationExists(reg) {
					// log phantom IP, shared secret, ipv6 support
					logger.Debugf("Duplicate registration: %v %s\n", reg.IDString(), reg.RegistrationSource)
					cj.Stat().AddDupReg()

					// Track the received registration, if it is already tracked
					// it will just update the record
					err := regManager.TrackRegistration(reg)
					if err != nil {
						logger.Errorln("error tracking registration: ", err)
						cj.Stat().AddErrReg()
					}
					return
				}

				// log phantom IP, shared secret, ipv6 support
				logger.Debugf("New registration: %s %v\n", reg.IDString(), reg.String())

				// Track the received registration
				err := regManager.TrackRegistration(reg)
				if err != nil {
					logger.Errorln("error tracking registration: ", err)
					cj.Stat().AddErrReg()
				}

				// If registration is trying to connect to a covert address that
				// is blocklisted consider registration INVALID and continue
				covert := conf.ParseOrResolveBlocklisted(reg.Covert)
				if covert == "" {
					// We log client IPs for clients attempting to connect to
					// blocklisted covert addresses.
					logger.Infof("Dropping reg, malformed or blocklisted covert: %v, %s -> %s", reg.IDString(), reg.GetRegistrationAddress(), reg.Covert)
					cj.Stat().AddErrReg()
					return
				}

				// Overwrite provided covert with resolved address. This kind of
				// sucks because net.Dial can try multiple addresses for domain
				// names w/ multiple records when resolved and we lock to one
				// address. However, this step is required to prevent SSRF via
				// DNS rebinding. Clients generally shouldn't be providing
				// hostnames as coverts anyways.
				reg.Covert = covert

				if !reg.PreScanned() {
					// New registration received over channel that requires liveness scan for the phantom
					liveness, response := regManager.PhantomIsLive(reg.DarkDecoy.String(), 443)

					// TODO JMWAMPLE remove this
					if liveness {
						logger.Warnf("Dropping registration %v -- live phantom: %v\n", reg.IDString(), response)
						if response.Error() == lt.CachedPhantomMessage {
							cj.Stat().AddLivenessCached()
						}
						cj.Stat().AddLivenessFail()
						return
					}
					cj.Stat().AddLivenessPass()
				}

				if conf.EnableShareOverAPI && *reg.RegistrationSource == pb.RegistrationSource_Detector {
					// Registration received from decoy-registrar, share over API if enabled.
					go tryShareRegistrationOverAPI(reg, conf.PreshareEndpoint)
				}

				if conf.IsBlocklistedPhantom(reg.DarkDecoy) {
					// Note: Phantom blocklist is applied at this stage because the phantom may only be blocked on this
					// station. We may want other stations to be informed about the registration, but prevent this station
					// specifically from handling / interfering in any subsequent connection. See PR #75
					logger.Warnf("ignoring registration with blocklisted phantom: %s %v", reg.IDString(), reg.DarkDecoy)
					cj.Stat().AddErrReg()
					return
				}

				// validate the registration
				regManager.AddRegistration(reg)
				logger.Debugf("Adding registration %v\n", reg.IDString())
				cj.Stat().AddReg(reg.DecoyListVersion, reg.RegistrationSource)

			}(reg)

		}
	}
}

func tryShareRegistrationOverAPI(reg *cj.DecoyRegistration, apiEndpoint string) {
	logger := sharedLogger
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

func executeHTTPRequest(reg *cj.DecoyRegistration, payload []byte, apiEndpoint string) error {
	logger := sharedLogger
	resp, err := http.Post(apiEndpoint, "", bytes.NewReader(payload))
	if err != nil {
		logger.Errorf("%v failed to do HTTP request to registration endpoint %s: %v", reg.IDString(), apiEndpoint, err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		logger.Errorf("%v got non-success response code %d from registration endpoint %v", reg.IDString(), resp.StatusCode, apiEndpoint)
		return fmt.Errorf("non-success response code %d on %s", resp.StatusCode, apiEndpoint)
	}

	return nil
}

// handleRegMessage ingests messages from zmq and parses them into
// registration structs for the registration manager to process.
// **NOTE** : Avoid ALL blocking calls (i.e. things that require a lock on the
// registration tracking structs) in this method because it will block and
// prevent the station from ingesting new registrations.
// **NOTE2**: If the registration address is IPv4 we will create registrations
// for both IPv4 decoy and IPv6 decoy. However, If the client Address from
// registrations is IPv6 we will only create an ipv6 registration because
//  1. we have no client address to match on for ipv4
//  2. the client _should_ support ipv6
func handleRegMessage(msg []byte, regManager *cj.RegistrationManager, conf *cj.Config) ([]*cj.DecoyRegistration, error) {
	logger := sharedLogger

	parsed := &pb.C2SWrapper{}
	err := proto.Unmarshal(msg, parsed)
	if err != nil {
		logger.Errorf("Failed to unmarshall ClientToStation: %v", err)
		return nil, err
	}

	// if either addres is not provided (reg came over api / client ip
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
	var newRegs []*cj.DecoyRegistration

	// if the clients address is ipv6 skip creating an ipv4 registration.
	if parsed.GetRegistrationPayload().GetV4Support() && conf.EnableIPv4 && sourceAddr.To4() != nil {
		reg, err := regManager.NewRegistrationC2SWrapper(parsed, false)
		if err != nil {
			logger.Errorf("Failed to create registration from v4 C2S: %v", err)
			return nil, err
		}

		// Received new registration, parse it and return
		newRegs = append(newRegs, reg)
	}

	if parsed.GetRegistrationPayload().GetV6Support() && conf.EnableIPv6 {
		reg, err := regManager.NewRegistrationC2SWrapper(parsed, true)
		if err != nil {
			logger.Errorf("Failed to create registration from v6 C2S: %v", err)
			return nil, err
		}
		// add to list of new registrations to be processed.
		newRegs = append(newRegs, reg)
	}

	// log decoy connection and id string
	if len(newRegs) > 0 {
		if logClientIP {
			logger.Debugf("received registration: '%v' -> '%v' %v %s\n", sourceAddr, phantomAddr, newRegs[0].IDString(), parsed.GetRegistrationSource())
		} else {
			logger.Debugf("received registration: '_' -> '%v' %v %s\n", phantomAddr, newRegs[0].IDString(), parsed.GetRegistrationSource())
		}
	}
	return newRegs, nil
}

var sharedLogger *log.Logger
var logClientIP = false

func main() {
	rand.Seed(time.Now().UnixNano())
	var err error
	var zmqAddress string
	flag.StringVar(&zmqAddress, "zmq-address", "ipc://@zmq-proxy", "Address of ZMQ proxy")
	flag.Parse()

	// Init stats
	cj.Stat()

	// parse toml station configuration
	conf, err := cj.ParseConfig()
	if err != nil {
		log.Fatalf("failed to parse app config: %v", err)
	}

	// parse & set log level for the lib for which sets the default level all
	// loggers created by subroutines routines.
	var logLevel = log.ErrorLevel
	if conf.LogLevel != "" {
		logLevel, err = log.ParseLevel(conf.LogLevel)
		if err != nil || logLevel == log.UnknownLevel {
			log.Fatal(err)
		}
	}
	log.SetLevel(logLevel)

	regManager := cj.NewRegistrationManager()
	sharedLogger = regManager.Logger
	logger := sharedLogger

	// Should we log client IP addresses
	logClientIP, err = strconv.ParseBool(os.Getenv("LOG_CLIENT_IP"))
	if err != nil {
		logger.Errorf("failed parse client ip logging setting: %v\n", err)
		logClientIP = false
	}

	// If CacheExpirationTime is set enable the Cached liveness tester.
	if conf.CacheExpirationTime != "" {
		clt, err := lt.New(&lt.Config{CacheDuration: conf.CacheExpirationTime})
		if err != nil {
			logger.Fatal(err)
		}
		regManager.LivenessTester = clt
	}
	cj.Stat().AddStatsModule(regManager.LivenessTester)
	cj.Stat().AddStatsModule(cj.GetProxyStats())
	// cj.Stat().AddStatsModule(regmManager)
	// cj.Stat().AddStatsModule(connStats)

	// Add registration channel options
	err = regManager.AddTransport(pb.TransportType_Min, min.Transport{})
	if err != nil {
		logger.Errorf("failed to add transport: %v", err)
	}
	err = regManager.AddTransport(pb.TransportType_Obfs4, obfs4.Transport{})
	if err != nil {
		logger.Errorf("failed to add transport: %v", err)
	}

	// Receive registration updates from ZMQ Proxy as subscriber
	regChan := make(chan interface{}, 10000)
	zmqIngester := cj.NewZMQIngest(zmqAddress, regChan, &conf.ZMQConfig)
	go zmqIngester.RunZMQ()
	go handleRegUpdates(regManager, regChan, conf)

	cj.Stat().AddStatsModule(zmqIngester)

	// Periodically clean old registrations
	go func() {
		for {
			time.Sleep(3 * time.Minute)
			regManager.RemoveOldRegistrations()
		}
	}()

	// listen for and handle incoming proxy traffic
	listenAddr := &net.TCPAddr{IP: nil, Port: 41245, Zone: ""}
	ln, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		logger.Errorf("failed to listen on %v: %v\n", listenAddr, err)
		return
	}
	defer ln.Close()
	logger.Infof("[STARTUP] Listening on %v\n", ln.Addr())

	for {
		newConn, err := ln.AcceptTCP()
		if err != nil {
			logger.Errorf("[ERROR] failed to AcceptTCP on %v: %v\n", ln.Addr(), err)
			continue
		}
		go handleNewConn(regManager, newConn)
	}
}
