package main

import (
	"github.com/sirupsen/logrus"
)

var (
	iface  = "wlp4s0"
	buffer = int32(1600)
	filter = "tcp and port 22 and not src 192.168.1.104"
)

func main() {

	conf := &Config{
		FilterList:       []string{"192.168.1.104"},
		Tags:             []string{"abcdefghi.jklmnopqrstuvw.xyz"},
		StatsFrequency:   3,
		CleanupFrequency: 3,

		Source: &DataSourceConfig{
			DataSourceType: DataSourceIface,
			SnapLen:        buffer,
			Iface:          iface,
		},
	}

	logger := logrus.New()
	det, err := DetectorFromConfig(conf)
	if err != nil {
		logger.Fatal(err)
	}

	det.Logger = logger

	det.Run()
}
