package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/refraction-networking/gotapdance/pkg/dns-registrar/responder"
	log "github.com/sirupsen/logrus"
)

const keyLen = 32

// config defines the variables and options from the toml config file
type config struct {
	UdpAddr     string `toml:"addr"`
	ApiUrl      string `toml:"api_url"`
	BdApiUrl    string `toml:"bdapi_url"`
	Domain      string `toml:"domain"`
	PrivkeyPath string `toml:"private_key_path"`
	LogLevel    string `toml:"log_level"`
}

func run(forwarder *DnsRegForwarder) error {
	defer forwarder.Close()

	log.Println("Started Conjure DNS registration server")

	err := forwarder.RecvAndForward()
	if err != nil {
		log.Printf("Forwarder RecvAndForward returned error: %v", err)
		return err
	}

	return nil
}

func main() {
	var udpAddr string
	var apiUrl string
	var bdApiUrl string
	var domain string
	var privkeyPath string
	var pubkeyFilenameOut string
	var privkeyFilenameOut string
	var configPath string
	var logLevelStr string

	flag.StringVar(&udpAddr, "addr", "[::]:53", "UDP address to listen on")
	flag.StringVar(&domain, "domain", "", "base domain in requests")
	flag.StringVar(&apiUrl, "api-endpoint", "https://registration.refraction.network/api/register", "API endpoint to use when performing API registration")
	flag.StringVar(&bdApiUrl, "bdapi-endpoint", "https://registration.refraction.network/api/register-bidirectional", "API endpoint to use when performing API registration")
	flag.StringVar(&privkeyPath, "privkey", "", "server private key filename")
	flag.StringVar(&pubkeyFilenameOut, "pubkeyfilename", "", "generated server public key filename (only used with -genKey)")
	flag.StringVar(&privkeyFilenameOut, "privkeyfilename", "", "generated server private key filename (only used with -genKey)")
	flag.StringVar(&configPath, "config", "", "configuration file path")
	flag.StringVar(&logLevelStr, "loglevel", "info", "log level, one of the following: panic, fatal, error, warn, info, debug, trace")
	flag.Parse()

	logFormatter := &log.TextFormatter{
		FullTimestamp: true,
	}
	log.SetFormatter(logFormatter)

	if configPath != "" {
		var conf config
		_, err := toml.DecodeFile(configPath, &conf)
		if err != nil {
			log.Fatalf("Error in reading config file: %v", err)
		}

		udpAddr = conf.UdpAddr
		apiUrl = conf.ApiUrl
		bdApiUrl = conf.BdApiUrl
		domain = conf.Domain
		privkeyPath = conf.PrivkeyPath
		logLevelStr = conf.LogLevel
	}

	// parse & set log level
	logLevel, err := log.ParseLevel(logLevelStr)
	if err != nil {
		log.Fatal(err)
	}
	log.SetLevel(logLevel)

	if udpAddr == "" {
		fmt.Fprintf(os.Stderr, "must specify address to listen on\n")
		flag.Usage()
		os.Exit(2)
	}

	if domain == "" {
		fmt.Println("domain must be specified")
		flag.Usage()
		os.Exit(2)
	}

	privkey, err := ioutil.ReadFile(privkeyPath)
	privkey = privkey[:keyLen]
	if err != nil {
		log.Fatal(err)
	}

	respder, err := responder.NewDnsResponder(domain, udpAddr, privkey)
	if err != nil {
		log.Fatal(err)
	}

	forwarder, err := NewDnsRegForwarder(apiUrl, bdApiUrl, respder)
	if err != nil {
		log.Fatal(err)
	}

	err = run(forwarder)
	if err != nil {
		log.Fatal(err)
	}
}
