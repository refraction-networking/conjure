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
	defer regManager.Cleanup()

	// Should we log client IP addresses
	logClientIP, err = strconv.ParseBool(os.Getenv("LOG_CLIENT_IP"))
	if err != nil {
		logger.Errorf("failed parse client ip logging setting: %v\n", err)
		logClientIP = false
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

	connManager := newConnManager(nil)

	cj.Stat().AddStatsModule(zmqIngester)
	cj.Stat().AddStatsModule(regManager.LivenessTester)
	cj.Stat().AddStatsModule(cj.GetProxyStats())
	cj.Stat().AddStatsModule(regManager)
	cj.Stat().AddStatsModule(connManager)

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
	go connManager.acceptConnections(ctx, regManager, logger)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for sig := range sigCh {
		// Wait for close signal.
		if sig != syscall.SIGHUP {
			logger.Infof("received %s ... exiting\n", sig.String())
			break
		}

		// Use SigHUP to indicate config reload
		logger.Infoln("received SIGHUP ... reloading configs")

		// parse toml station configuration. If parse fails, log and abort
		// reload.
		newConf, err := cj.ParseConfig()
		if err != nil {
			log.Errorf("failed to parse app config: %v", err)
		} else {
			regManager.OnReload(newConf.RegConfig)
		}
	}

	cancel()
	wg.Wait()
	logger.Infof("shutdown complete")
}
