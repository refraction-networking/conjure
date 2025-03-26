package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	det "github.com/refraction-networking/conjure/application/detector"
	"github.com/sirupsen/logrus"
)

// var (
// 	iface  = "wlp4s0"
// 	buffer = int32(1600)
// 	filter = "tcp and port 22 and not src 192.168.1.104"
// )

// StationType defines enum of available pieces of the station that can be run
// individually or together.
type StationType string

const (
	// StationTypeApp runs an independent instance of the golang implementation
	// of the application portion of the station
	StationTypeApp StationType = "application"

	// StationTypeDet runs an independent instance of the golang implementation
	// of the detector portion of the station [Testing only]
	StationTypeDet = "detector"

	// StationTypeFull runs both the golang implementation of the application
	// and the detector and wires them together
	StationTypeFull = ""
)

func main() {

	// conf := &det.Config{
	// 	FilterList:       []string{"192.168.1.104"},
	// 	Tags:             []string{"abcdefghi.jklmnopqrstuvw.xyz"},
	// 	StatsFrequency:   3,
	// 	CleanupFrequency: 3,

	// 	Source: &det.DataSourceConfig{
	// 		DataSourceType: det.DataSourceIface,
	// 		SnapLen:        buffer,
	// 		Iface:          iface,
	// 	},
	// }

	logger := logrus.New()

	// Parse Config options from default configuration location
	conf, err := det.GetConfig()
	if err != nil {
		logger.Fatal(err)
	}

	// Create a detector
	detector, err := det.DetectorFromConfig(conf)
	if err != nil {
		logger.Fatal(err)
	}
	// override detector logger with global logger
	detector.Logger = logger

	// // // Set up Tun interfaces. [TODO]
	// err := iface.InitializeTunSet(num int, prefix string, iface string)
	// if err != nil {
	// 	logger.Fatalf(err)
	// }

	// Create root context for handling cancelation / teardown
	ctx, cancelFunc := context.WithCancel(context.Background())

	var stationType = StationType(os.Getenv("CJ_GOLANG_STATION_TYPE"))
	switch stationType {
	case StationTypeApp:
		// go app.Run(ctx)

	case StationTypeDet:
		go detector.Run(ctx)

	case StationTypeFull:
		// go app.Run(ctx)
		go detector.Run(ctx)

	default:
		logger.Fatalf("unknown golang station type")
	}

	// Handle sigterm and await termChan signal
	termChan := make(chan os.Signal)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

runloop:
	for {
		sig := <-termChan
		switch sig {
		case syscall.SIGHUP:
			//reload configs
			logger.Println("Reloading configuration files")
		default:
			logger.Printf("Received Signal %v\n", sig)
			break runloop

		}
	} // Blocks here until interrupted

	// Handle shutdown
	logger.Println("*****\nShutdown signal received\n*****")
	cancelFunc() // Signal cancellation to context.Context

	// // Teardown tun interfaces. [TODO]
	// err = iface.TeardownTunSet(num int, prefix string)
	// if err != nil {
	// 	logger.Fatalf(err)
	// }

}
