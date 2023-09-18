package main

import (
	"context"
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/refraction-networking/conjure/pkg/station"
	cj "github.com/refraction-networking/conjure/pkg/station/lib"
	"github.com/refraction-networking/conjure/pkg/station/log"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/min"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/obfs4"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/prefix"
	pb "github.com/refraction-networking/conjure/proto"
)

var sharedLogger *log.Logger

var enabledTransports = map[pb.TransportType]cj.Transport{
	pb.TransportType_Min:    min.Transport{},
	pb.TransportType_Obfs4:  obfs4.Transport{},
	pb.TransportType_Prefix: prefix.Transport{},
}

func main() {
	var err error
	var zmqAddress string
	flag.StringVar(&zmqAddress, "zmq-address", "ipc://@zmq-proxy", "Address of ZMQ proxy")
	flag.Parse()

	// Init stats
	cj.Stat()

	// parse toml station configuration
	conf, err := station.ConfigFromEnv()
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

	cjStation, err := station.New(conf)
	if err != nil {
		log.Fatalf("failed to create station: %v", err)
	}
	defer func() {
		station.Shutdown()
		logger.Infof("shutdown complete")
	}()

	ctx, cancel := context.WithCancel(context.Background())

	go acceptConnections(ctx, cjStation, logger)

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
		newConf, err := station.ConfigFromEnv()
		if err != nil {
			log.Errorf("failed to parse app config: %v", err)
		} else {
			regManager.OnReload(newConf.RegConfig)
		}
	}

	cancel()
}

func acceptConnections(ctx context.Context, config *station.Station, logger *log.Logger) {

	// listen for and handle incoming proxy traffic
	listenAddr := &net.TCPAddr{IP: nil, Port: 41245, Zone: ""}
	ln := cjStation.Listen(listenAddr)
	if err != nil {
		logger.Fatalf("failed to listen on %v: %v\n", listenAddr, err)
	}
	defer ln.Close()
	logger.Infof("[STARTUP] Listening on %v\n", ln.Addr())

	for {
		select {
		case <-ctx.Done():
			break
		default:
			newConn, err := ln.Accept()
			if err != nil {
				logger.Errorf("[ERROR] failed to AcceptTCP on %v: %v\n", ln.Addr(), err)
				continue
			}
			go func(conn net.Conn) {
				defer conn.Close()
				err := cjStation.ForwardProxy(conn)
				if err != nil {
					logger.Errorf("[ERROR] failed while proxying: %v\n", err)
				}
			}(newConn)
		}
	}
}
