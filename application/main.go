package main

import (
	"context"
	"flag"
	"math/rand"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	cj "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/liveness"
	"github.com/refraction-networking/conjure/application/log"
	"github.com/refraction-networking/conjure/application/transports/wrapping/min"
	"github.com/refraction-networking/conjure/application/transports/wrapping/obfs4"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

var sharedLogger *log.Logger
var logClientIP = false

var enabledTransports = map[pb.TransportType]cj.Transport{
	pb.TransportType_Min:   min.Transport{},
	pb.TransportType_Obfs4: obfs4.Transport{},
}

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

	regManager := cj.NewRegistrationManager(conf.RegConfig)
	sharedLogger = regManager.Logger
	logger := sharedLogger

	// Should we log client IP addresses
	logClientIP, err = strconv.ParseBool(os.Getenv("LOG_CLIENT_IP"))
	if err != nil {
		logger.Errorf("failed parse client ip logging setting: %v\n", err)
		logClientIP = false
	}

	// If CacheExpirationTime is set enable the Cached liveness tester.
	if conf.CacheExpirationTime != "" || conf.CacheExpirationNonLive != "" {
		clt, err := liveness.New(&liveness.Config{
			CacheDuration:        conf.CacheExpirationTime,
			CacheDurationNonLive: conf.CacheExpirationNonLive,
		})
		if err != nil {
			logger.Fatal(err)
		}
		regManager.LivenessTester = clt
	}

	// Add supported transport options for registration validation
	for transportType, transport := range enabledTransports {
		err = regManager.AddTransport(transportType, transport)
		if err != nil {
			logger.Errorf("failed to add transport: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	wg := new(sync.WaitGroup)
	regChan := make(chan interface{}, 10000)
	zmqIngester := cj.NewZMQIngest(zmqAddress, regChan, conf.ZMQConfig)

	cj.Stat().AddStatsModule(zmqIngester)
	cj.Stat().AddStatsModule(regManager.LivenessTester)
	cj.Stat().AddStatsModule(cj.GetProxyStats())
	// cj.Stat().AddStatsModule(regManager)
	// cj.Stat().AddStatsModule(connStats)

	// Periodically clean old registrations
	go func(ctx context.Context) {
		ticker := time.NewTicker(3 * time.Minute)
		for {
			select {
			case <-ctx.Done():
				break
			case <-ticker.C:
				regManager.RemoveOldRegistrations()
			}
		}
	}(ctx)

	// Receive registration updates from ZMQ Proxy as subscriber
	go zmqIngester.RunZMQ(ctx)
	wg.Add(1)
	go regManager.HandleRegUpdates(ctx, regChan, wg)
	go acceptConnections(ctx, regManager, logger)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range sigCh {
		// Wait for SIGINT.
		if sig != syscall.SIGHUP {
			break
		}

		// regManager.ReloadConfig()
	}

	cancel()
	wg.Wait()
}
