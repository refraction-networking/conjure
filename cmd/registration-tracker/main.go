package main

/*
	TODOs:
		- Automate prefix discovery
		- Restructure regtracker code base
*/

import (
	"context"
	"errors"
	"flag"
	"fmt"
	golog "log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/refraction-networking/conjure/pkg/phantoms"
	"github.com/refraction-networking/conjure/pkg/station/geoip"
	cj "github.com/refraction-networking/conjure/pkg/station/lib"
	"github.com/refraction-networking/conjure/pkg/station/log"
	"github.com/refraction-networking/conjure/pkg/transports"
	"github.com/refraction-networking/conjure/pkg/transports/connecting/dtls"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/min"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/obfs4"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/prefix"
	pb "github.com/refraction-networking/conjure/proto"

	"google.golang.org/protobuf/proto"
)

var (
	ErrInvalidCC = errors.New("Invalid CC")
	ErrIPtoCC = errors.New("IP to CC failed")
	ErrIPtoASN = errors.New("IP to ASN failed")
	ErrDupReg = errors.New("duplicate registration")
)


type transportStats struct {
	cc                         string
	minCount                   int64
	dtlsCount                  int64
	obfs4Count                 int64
	unknownTransportCount      int64
	prefixCount                int64
	prefixMinCount             int64
	prefixGetLongCount         int64
	prefixPostLongCount        int64
	prefixHTTPRespCount        int64
	prefixTLSClientHelloCount  int64
	prefixTLSServerHelloCount  int64
	prefixTLSAlertWarningCount int64
	prefixTLSAlertFatalCount   int64
	prefixDNSOverTCPCount      int64
	prefixOpenSSH2Count        int64
	prefixUnknownCount         int64
}

type regStats struct {
	logger          *log.Logger
	m               *sync.Mutex               // Lock for registrations map
	v4Registrations map[uint]*transportStats  // Map from ASNs to transportStats
	v6Registrations map[uint]*transportStats  // Map from ASNs to transportStats
	currRegIds	map[string]int		  // Map for regIds to their count during the current ticker window
	prevRegIds	map[string]int		  // Map for regIds to their count during the previous ticker window
	GeoIP           geoip.Database
}

var enabledTransports = map[pb.TransportType]cj.Transport{
	pb.TransportType_Min:    min.Transport{},
	pb.TransportType_Obfs4:  obfs4.Transport{},
	pb.TransportType_Prefix: prefix.DefaultSet(),
	pb.TransportType_DTLS:   dtls.Transport{},
}

func (c *transportStats) GetCounts() string {

	return fmt.Sprintf("%d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
		atomic.LoadInt64(&c.minCount),
		atomic.LoadInt64(&c.dtlsCount),
		atomic.LoadInt64(&c.obfs4Count),
		atomic.LoadInt64(&c.unknownTransportCount),
		atomic.LoadInt64(&c.prefixCount),
		atomic.LoadInt64(&c.prefixMinCount),
		atomic.LoadInt64(&c.prefixGetLongCount),
		atomic.LoadInt64(&c.prefixPostLongCount),
		atomic.LoadInt64(&c.prefixHTTPRespCount),
		atomic.LoadInt64(&c.prefixTLSClientHelloCount),
		atomic.LoadInt64(&c.prefixTLSServerHelloCount),
		atomic.LoadInt64(&c.prefixTLSAlertWarningCount),
		atomic.LoadInt64(&c.prefixTLSAlertFatalCount),
		atomic.LoadInt64(&c.prefixDNSOverTCPCount),
		atomic.LoadInt64(&c.prefixOpenSSH2Count),
		atomic.LoadInt64(&c.prefixUnknownCount),
	)
}

func (c *transportStats) IncrementCount(reg *cj.DecoyRegistration) {
	transport := *reg.TransportPtr
	switch transport.Name() {
	case "MinTransport":
		atomic.AddInt64(&c.minCount, 1)
	case "dtls":
		atomic.AddInt64(&c.dtlsCount, 1)
	case "obfs4":
		atomic.AddInt64(&c.obfs4Count, 1)
	case "PrefixTransport":
		atomic.AddInt64(&c.prefixCount, 1)
		switch prefix.PrefixID(reg.TransportParams().(*pb.PrefixTransportParams).GetPrefixId()).Name() {
		// Becuase reg.TransportParams() returns any, we need to cast it to *pb.PrefixTransportParams and
		// GetPrefixId() to be able to get the prefix name
		case "Min":
			atomic.AddInt64(&c.prefixMinCount, 1)
		case "GetLong":
			atomic.AddInt64(&c.prefixGetLongCount, 1)
		case "PostLong":
			atomic.AddInt64(&c.prefixPostLongCount, 1)
		case "HTTPResp":
			atomic.AddInt64(&c.prefixHTTPRespCount, 1)
		case "TLSClientHello":
			atomic.AddInt64(&c.prefixTLSClientHelloCount, 1)
		case "TLSServerHello":
			atomic.AddInt64(&c.prefixTLSServerHelloCount, 1)
		case "TLSAlertWarning":
			atomic.AddInt64(&c.prefixTLSAlertWarningCount, 1)
		case "TLSAlertFatal":
			atomic.AddInt64(&c.prefixTLSAlertFatalCount, 1)
		case "DNSOverTCP":
			atomic.AddInt64(&c.prefixDNSOverTCPCount, 1)
		case "OpenSSH2":
			atomic.AddInt64(&c.prefixOpenSSH2Count, 1)
		default:
			atomic.AddInt64(&c.prefixUnknownCount, 1)
		}
	default:
		atomic.AddInt64(&c.unknownTransportCount, 1)
	}
}

func (rs *regStats) PrintAndReset() {
	rs.m.Lock()
	defer rs.m.Unlock()

	for i, val := range [2]map[uint]*transportStats{rs.v4Registrations, rs.v6Registrations} {
		ip_ver := 4
		if i == 1 {
			ip_ver = 6
		}
		for asn, counts := range val {
			rs.logger.Infof("regtrack (IPv%d): %d %s %s",
				ip_ver,
				asn,
				counts.cc,
				counts.GetCounts(),
			)
		}
	}
	rs.v4Registrations = make(map[uint]*transportStats)
	rs.v6Registrations = make(map[uint]*transportStats)
	rs.prevRegIds = make(map[string]int)
	for key, val := range rs.currRegIds {
		rs.prevRegIds[key] = val
	}
	rs.currRegIds = make(map[string]int)
}

func (rs *regStats) AddRegistration(asn uint, cc string, isIPv4 bool, reg *cj.DecoyRegistration) error {
	rs.m.Lock()
	defer rs.m.Unlock()
	if cc != "" {
		// GeoIP tracking
		if isIPv4 {
			if _, okAsn := rs.v4Registrations[asn]; !okAsn {
				rs.v4Registrations[asn] = &transportStats{}
				rs.v4Registrations[asn].cc = cc
			}
			rs.v4Registrations[asn].IncrementCount(reg)
		} else {
			if _, okAsn := rs.v6Registrations[asn]; !okAsn {
				rs.v6Registrations[asn] = &transportStats{}
				rs.v6Registrations[asn].cc = cc
			}
			rs.v6Registrations[asn].IncrementCount(reg)
		}
	} else {
		return ErrInvalidCC
	}
	return nil
}

func (rs *regStats) ProcessRegistration(sourceAddr net.IP, reg *cj.DecoyRegistration) error {
	cc, err := rs.GeoIP.CC(sourceAddr)
	if err != nil {
		return ErrIPtoCC
	}
	asn, err := rs.GeoIP.ASN(sourceAddr)
	if err != nil {
		return ErrIPtoASN
	}

	isIPv4 := sourceAddr.To4() != nil

	// reg.IDString() could be used instead of string(reg.Keys.SharedSecret), 
	// but we don't need encoded strings as keys. Using bytes is better in terms
	// of performance. Might consider using reg.IDString() in case debugging 
	// registrations is needed
	strSharedKey := string(reg.Keys.SharedSecret)
	rs.m.Lock()
	if _, foundInCurr := rs.currRegIds[strSharedKey]; foundInCurr {
		rs.currRegIds[strSharedKey]++
		rs.m.Unlock()
		return ErrDupReg
        } else {
		if _, foundInPrev := rs.prevRegIds[strSharedKey]; foundInPrev {
			rs.prevRegIds[strSharedKey]++
			rs.currRegIds[strSharedKey] = 1
			rs.m.Unlock()
			return ErrDupReg
		} else {
			rs.currRegIds[strSharedKey] = 1
			rs.m.Unlock()
			err = rs.AddRegistration(asn, cc, isIPv4, reg)
			if err != nil {
				// handle err if needed
				return err
			}
		}
	}
	return nil
}

func handleC2SError(logger *log.Logger, IPVerSupport string, err error, reg *cj.DecoyRegistration){

        if errors.Is(err, phantoms.ErrLegacyMissingAddrs) ||
                errors.Is(err, phantoms.ErrLegacyAddrSelectBug) ||
                errors.Is(err, phantoms.ErrLegacyV0SelectionBug) ||
                errors.Is(err, transports.ErrUnknownTransport) {
                logger.Debugf("DEBUG: unexpected err creating %s registration: %v, %v", IPVerSupport, err, reg)
        } else {
                logger.Errorf("unexpected err creating %s registration: %v, %v", IPVerSupport, err, reg)
        }
}

func main() {
	var zmqAddress string
	flag.StringVar(&zmqAddress, "zmq-address", "ipc://@zmq-proxy", "Address of ZMQ proxy")
	flag.Parse()

	logger := log.New(os.Stdout, "[REGTRACK] ", golog.Ldate|golog.Lmicroseconds)

	// parse toml station configuration
	conf, err := cj.ParseConfig()
	if err != nil {
		logger.Fatalf("failed to parse app config: %v", err)
	}

	privkey, err := conf.ParsePrivateKey()
	if err != nil {
		logger.Fatalf("error parseing private key: %s", err)
	}

	geoipDB, err := geoip.New(conf.RegConfig.DBConfig)
	if err != nil {
		logger.Fatalf("failed to create geoip database: %v", err)
	}

	regstats := regStats{
		logger:          logger,
		m:               &sync.Mutex{},
		v4Registrations: make(map[uint]*transportStats),
		v6Registrations: make(map[uint]*transportStats),
		currRegIds:      make(map[string]int),
		prevRegIds:      make(map[string]int),
		GeoIP:           geoipDB,
	}

	ctx, _ := context.WithCancel(context.Background())
	regChan := make(chan interface{}, 10000)
	zmqIngester, err := cj.NewZMQIngest(zmqAddress, regChan, privkey, conf.ZMQConfig)
	if err != nil {
		logger.Fatal("error creating ZMQ Ingest: %w", err)
	}

	// Receive registration updates from ZMQ Proxy as subscriber
	go zmqIngester.RunZMQ(ctx)

	regManager := cj.NewRegistrationManager(&cj.RegConfig{})

	// Add supported transport options for registration validation
	for transportType, transport := range enabledTransports {
		err = regManager.AddTransport(transportType, transport)
		if err != nil {
			logger.Fatalf("failed to add transport: %v", err)
		}
	}

	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			regstats.PrintAndReset()
		}
	}()

	msgChan := make(chan interface{}, 10000)

	// Read from regChan to which the zmqIngester writes
	for data := range regChan {

		select {
		case <- ctx.Done():
			logger.Fatal("closing all ingest threads")
		case msgChan <- data:
		default:
			logger.Tracef("dropping registration")
		}
		msg, ok := (<-msgChan).([]byte)
		if !ok {
			logger.Tracef("failed to convert registration into proper type")
		}

		parsed := &pb.C2SWrapper{}
		err = proto.Unmarshal(msg, parsed)
		if err != nil {
			logger.Errorf("failed to unmarshall ClientToStation: %v", err)
		}

		if parsed.GetRegistrationAddress() == nil {
			parsed.RegistrationAddress = make([]byte, 16)
		}
		if parsed.GetDecoyAddress() == nil {
			parsed.DecoyAddress = make([]byte, 16)
		}

		var sourceAddr = net.IP(parsed.GetRegistrationAddress())

		var reg *cj.DecoyRegistration

		// gotapdance cli support v6 by default, so Getv6Support() will typically be true
		// Also, clients IP version support can either be (v6 and v4) or v4 alone
		if parsed.GetRegistrationPayload().GetV6Support() {
			// registration indicates support for v6 
			reg, err = regManager.NewRegistrationC2SWrapper(parsed, true)
			if err != nil {
				handleC2SError(logger, "v6-supported", err, reg)
				continue
			}
		} else if parsed.GetRegistrationPayload().GetV4Support() && sourceAddr.To4() != nil {
			// registration indicates NO support for v6 
			reg, err = regManager.NewRegistrationC2SWrapper(parsed, false)
                        if err != nil {
                                handleC2SError(logger, "strictly-v4-supported", err, reg)
                                continue
                        }
		} else {
			logger.Errorf("reached an edge case where the client neither supports v4 or v6")
			continue
		}

		go func(ip net.IP, registration *cj.DecoyRegistration) {
			err = regstats.ProcessRegistration(ip, registration)
			if err != nil {
				if errors.Is(err, ErrInvalidCC) ||
					errors.Is(err, ErrIPtoCC) ||
					errors.Is(err, ErrIPtoASN) ||
					errors.Is(err, ErrDupReg) {
					logger.Debugf("DEBUG: unexpected err processing registration: %v", err)
				} else {
					logger.Errorf("unexpected err processing registration: %v", err)
				}
			}
		}(sourceAddr, reg)
	}
}
