package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	zmq "github.com/pebbe/zmq4"
	"github.com/refraction-networking/conjure/pkg/apiregserver"
	"github.com/refraction-networking/conjure/pkg/dnsregserver"
	"github.com/refraction-networking/conjure/pkg/metrics"
	"github.com/refraction-networking/conjure/pkg/regprocessor"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type regServer interface {
	ListenAndServe() error
}

// config defines the variables and options from the toml config file
type config struct {
	DNSListenAddr      string   `toml:"dns_listen_addr"`
	Domain             string   `toml:"domain"`
	DNSPrivkeyPath     string   `toml:"dns_private_key_path"`
	APIPort            uint16   `toml:"api_port"`
	ZMQAuthVerbose     bool     `toml:"zmq_auth_verbose"`
	ZMQAuthType        string   `toml:"zmq_auth_type"`
	ZMQPort            uint16   `toml:"zmq_port"`
	ZMQBindAddr        string   `toml:"zmq_bind_addr"`
	ZMQPrivateKeyPath  string   `toml:"zmq_privkey_path"`
	StationPublicKeys  []string `toml:"station_pubkeys"`
	ClientConfPath     string   `toml:"clientconf_path"`
	LogLevel           string   `toml:"log_level"`
	LogMetricsInterval uint16   `toml:"log_metrics_interval"`
}

// parseClientConf parse the latest ClientConf based on path file
func parseClientConf(path string) (*pb.ClientConf, error) {
	// Create empty client config protobuf to return in case of error
	emptyPayload := &pb.ClientConf{}

	// Check that the filepath passed in exists
	if _, err := os.Stat(path); err != nil {
		fmt.Println("filepath does not exist:", path)
		return emptyPayload, err
	}

	// Open file path that stores the client config
	in, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("failed to read client config filepath:", err)
		return emptyPayload, err
	}

	// Create protobuf struct
	payload := &pb.ClientConf{}

	// Unmarshal into protobuf struct
	if err = proto.Unmarshal(in, payload); err != nil {
		fmt.Println("failed to decode protobuf body:", err)
		return emptyPayload, err
	}

	// If no error, return the payload (clientConf pb)
	return payload, nil
}

func run(regServers []regServer) {
	log.Infof("Started Conjure registration server")

	var wg sync.WaitGroup

	for _, curRegServer := range regServers {
		wg.Add(1)
		go func(regServer regServer) {
			defer wg.Done()
			err := regServer.ListenAndServe()
			if err != nil {
				log.Errorf("regServer stopped: %v", err)
			}
		}(curRegServer)
	}

	wg.Wait()
}

func readKey(path string) ([]byte, error) {
	privkey, err := os.ReadFile(path)
	privkey = privkey[:32]
	if err != nil {
		return nil, err
	}
	return privkey, nil
}

func readKeyAndEncode(path string) (string, error) {
	keyBytes, err := readKey(path)
	if err != nil {
		return "", err
	}
	privkey := zmq.Z85encode(string(keyBytes))
	return privkey, nil
}

func main() {
	var configPath string

	flag.StringVar(&configPath, "config", "", "configuration file path")
	flag.Parse()

	if configPath == "" {
		fmt.Fprintf(os.Stderr, "-config is a required flag")
		flag.Usage()
		os.Exit(2)
	}

	logFormatter := &log.TextFormatter{
		FullTimestamp: true,
	}

	log.SetFormatter(logFormatter)

	var conf config
	_, err := toml.DecodeFile(configPath, &conf)
	if err != nil {
		log.Fatalf("Error in reading config file: %v", err)
	}

	logClientIP, err := strconv.ParseBool(os.Getenv("LOG_CLIENT_IP"))
	if err != nil {
		log.Errorf("failed parse client ip logging setting: %v\n", err)
		logClientIP = false
	}

	logLevel, err := log.ParseLevel(conf.LogLevel)
	if err != nil {
		log.Fatal(err)
	}
	log.SetLevel(logLevel)

	zmqPrivkey, err := readKeyAndEncode(conf.ZMQPrivateKeyPath)
	if err != nil {
		log.Fatal(err)
	}

	metrics := metrics.NewMetrics(log.NewEntry(log.StandardLogger()), time.Duration(conf.LogMetricsInterval)*time.Second)

	var processor *regprocessor.RegProcessor

	switch conf.ZMQAuthType {
	case "CURVE":
		processor, err = regprocessor.NewRegProcessor(conf.ZMQBindAddr, conf.ZMQPort, zmqPrivkey, conf.ZMQAuthVerbose, conf.StationPublicKeys, metrics)
	case "NULL":
		processor, err = regprocessor.NewRegProcessorNoAuth(conf.ZMQBindAddr, conf.ZMQPort, metrics)
	default:
		log.Fatalf("Unknown ZMQ auth type: %s", conf.ZMQAuthType)
	}

	if err != nil {
		log.Fatal(err)
	}

	latestClientConf, err := parseClientConf(conf.ClientConfPath)
	if err != nil {
		log.Fatal(err)
	}

	dnsPrivKey, err := readKey(conf.DNSPrivkeyPath)
	if err != nil {
		log.Fatal(err)
	}

	dnsRegServer, err := dnsregserver.NewDNSRegServer(conf.Domain, conf.DNSListenAddr, dnsPrivKey, processor, latestClientConf.GetGeneration(), log.WithField("registrar", "DNS"), metrics)
	if err != nil {
		log.Fatal(err)
	}

	apiRegServer, err := apiregserver.NewAPIRegServer(conf.APIPort, processor, latestClientConf, log.WithField("registrar", "API"), logClientIP, metrics)
	if err != nil {
		log.Fatal(err)
	}

	regServers := []regServer{dnsRegServer, apiRegServer}

	run(regServers)
}
