package station

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/dtls/dnat"
	"github.com/refraction-networking/conjure/pkg/log"
	"github.com/refraction-networking/conjure/pkg/station/connection"
	"github.com/refraction-networking/conjure/pkg/station/lib"
	"github.com/refraction-networking/conjure/pkg/station/liveness"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/prefix"
	pb "github.com/refraction-networking/conjure/proto"
)

// PrivateKeyLength is the expected length of the station (ed25519) private key in bytes.
const PrivateKeyLength = 32

var (
	// ErrNotImplemented is returned when a method is not implemented.
	ErrNotImplemented = liveness.ErrNotImplemented

	// ErrNonConjureConn is returned when a non-conjure connection is passed to a conjure method.
	errNonConjureConn = "cannot use %s on non-conjure connection"
)

var (
	// sharedLogger is the default logger for the station package.
	sharedLogger *log.Logger
)

// Station is a Conjure station. Running all required routines based on the provided configuration.
type Station struct {
	regManager  *lib.RegistrationManager
	connManager *connection.ConnHandler
	stats       []*lib.Stats

	enabledTransports map[pb.TransportType]interfaces.TransportSS

	wg *sync.WaitGroup
}

type listener struct {
	initialized bool
	listener    net.Listener
}

func New(ctx context.Context, conf *Config) (*Station, error) {

	connManager := connection.NewConnManager(conf.ConnManagerConfig)
	enabledTransports := make(map[pb.TransportType]interfaces.TransportSS)

	conf.RegConfig.ConnectingStats = connManager

	regManager := lib.NewRegistrationManager(conf.RegConfig)

	logIPDTLS := func(logger func(asn uint, cc, tp string)) func(*net.IP) {
		return func(ip *net.IP) {
			cc, err := regManager.GeoIP.CC(*ip)
			if err != nil {
				return
			}

			var asn uint = 0
			if cc != "unk" {
				asn, err = regManager.GeoIP.ASN(*ip)
				if err != nil {
					return
				}
			}

			logger(asn, cc, "dtls")
		}
	}

	dtlsbuilder := dnat.NewDNAT
	dtlsTransport, err := connManager.BuildDTLSTransport(dtlsbuilder, logIPDTLS)

	if err != nil {
		log.Fatalf("failed to setup dtls: %v", err)
	}
	enabledTransports[pb.TransportType_DTLS] = dtlsTransport

	sharedLogger = regManager.Logger
	logger := sharedLogger
	defer regManager.Cleanup()

	// Should we log client IP addresses
	logClientIP, err := strconv.ParseBool(os.Getenv("LOG_CLIENT_IP"))
	if err != nil {
		logger.Errorf("failed parse client ip logging setting: %v\n", err)
		logClientIP = false
	} else {
		conf.LogClientIP = logClientIP
	}

	privkey, err := conf.ParsePrivateKey()
	if err != nil {
		logger.Fatalf("error parseing private key: %s", err)
	}

	var prefixTransport lib.Transport
	if conf.DisableDefaultPrefixes {
		prefixTransport, err = prefix.New(privkey, conf.PrefixFilePath)
	} else {
		prefixTransport, err = prefix.Default(privkey, conf.PrefixFilePath)
	}
	if err != nil {
		logger.Errorf("Failed to parse provided custom prefix transport file: %s", err)
	} else {
		enabledTransports[pb.TransportType_Prefix] = prefixTransport
	}

	// Add supported transport options for registration validation
	for transportType, transport := range enabledTransports {
		err = regManager.AddTransport(transportType, transport)
		if err != nil {
			logger.Errorf("failed to add transport: %v", err)
		}
	}

	wg := new(sync.WaitGroup)
	regChan := make(chan interface{}, 10000)
	zmqIngester, err := lib.NewZMQIngest(conf.ZMQConfig.LocalZmqAddress, regChan, privkey, conf.ZMQConfig)
	if err != nil {
		logger.Fatal("error creating ZMQ Ingest: %w", err)
	}

	lib.Stat().AddStatsModule(zmqIngester, false)
	lib.Stat().AddStatsModule(regManager.LivenessTester, false)
	lib.Stat().AddStatsModule(lib.GetProxyStats(), false)
	lib.Stat().AddStatsModule(regManager, false)
	lib.Stat().AddStatsModule(connManager, true)

	// Periodically clean old registrations
	wg.Add(1)
	go func(ctx context.Context, wg *sync.WaitGroup) {
		defer wg.Done()

		ticker := time.NewTicker(3 * time.Minute)
		for {
			select {
			case <-ticker.C:
				regManager.RemoveOldRegistrations()
			case <-ctx.Done():
				return
			}
		}
	}(ctx, wg)

	// Receive registration updates from ZMQ Proxy as subscriber
	go zmqIngester.RunZMQ(ctx)
	wg.Add(1)
	go regManager.HandleRegUpdates(ctx, regChan, wg)

	return &Station{
		regManager:        regManager,
		connManager:       &connManager,
		stats:             []*lib.Stats{lib.Stat()},
		enabledTransports: enabledTransports,
		wg:                wg,
	}, nil
}

// Listen creates a new listener for the station which gives back a listener that can be used to
// accept connections in the pattern of the net package.
func Listen(network, address string) (net.Listener, error) {
	conf, err := ConfigFromEnv()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	station, err := New(ctx, conf)
	if err != nil {
		return nil, err
	}

	return station.Listen(ctx, network, address)
}

// Listen creates a new listener for the station which gives back a listener that can be used to
// accept connections in the pattern of the net package. Building a listener in this way allows the
// caller to specify the context.
func (s *Station) Listen(ctx context.Context, network, addr string) (net.Listener, error) {
	return s, nil
}

// Accept accepts a new connection from the listener.
func (s *Station) Accept() (net.Conn, error) {
	return nil, ErrNotImplemented
}

// Close closes the listener
// Any blocked Accept operations will be unblocked and return errors.
func (s *Station) Close() error {
	return ErrNotImplemented
}

// Addr returns the listener's network address.
func (s *Station) Addr() net.Addr {
	return net.Addr(nil)
}

// Shutdown shuts down the station.
func (s *Station) Shutdown() {
	s.Close()
	s.regManager.Shutdown()
	s.wg.Wait()
}

// ForwardProxy provides a Conjure specific transparent forward proxy which gives the ability to
// track statistics based on metadata associated with the registration such as transport type /
// parameters, phantom addr / subnet / port, client ASN / CC, etc.
func (s *Station) ForwardProxy(conn net.Conn) error {
	cjConn, ok := conn.(*connection.Conn)
	if !ok {
		return fmt.Errorf(errNonConjureConn, "Station.ForwardProxy")
	}

	lib.Proxy(&cjConn.DecoyRegistration, cjConn, s.regManager.Logger)
	return nil
}
