package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/refraction-networking/gotapdance/pkg/dns-registrar/encryption"
	"github.com/refraction-networking/gotapdance/pkg/dns-registrar/responder"
)

type config struct {
	UdpAddr     string `toml:"addr"`
	ApiUrl      string `toml:"api_url"`
	BdApiUrl    string `toml:"bdapi_url"`
	Domain      string `toml:"domain"`
	PrivkeyPath string `toml:"private_key_path"`
}

// readKeyFromFile reads a key from a named file.
func readKeyFromFile(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return encryption.ReadKey(f)
}

// generateKeypair generates a private key and the corresponding public key. If
// privkeyFilename and pubkeyFilename are respectively empty, it prints the
// corresponding key to standard output; otherwise it saves the key to the given
// file name. The private key is saved with mode 0400 and the public key is
// saved with 0666 (before umask). In case of any error, it attempts to delete
// any files it has created before returning.
func generateKeypair(privkeyFilename, pubkeyFilename string) (err error) {
	// Filenames to delete in case of error (avoid leaving partially written
	// files).
	var toDelete []string
	defer func() {
		for _, filename := range toDelete {
			fmt.Fprintf(os.Stderr, "deleting partially written file %s\n", filename)
			if closeErr := os.Remove(filename); closeErr != nil {
				fmt.Fprintf(os.Stderr, "cannot remove %s: %v\n", filename, closeErr)
				if err == nil {
					err = closeErr
				}
			}
		}
	}()

	privkey, err := encryption.GeneratePrivkey()
	if err != nil {
		return err
	}
	pubkey := encryption.PubkeyFromPrivkey(privkey)

	if privkeyFilename != "" {
		// Save the privkey to a file.
		f, err := os.OpenFile(privkeyFilename, os.O_RDWR|os.O_CREATE, 0400)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, privkeyFilename)
		_, err = fmt.Fprintf(f, "%x\n", privkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	if pubkeyFilename != "" {
		// Save the pubkey to a file.
		f, err := os.Create(pubkeyFilename)
		if err != nil {
			return err
		}
		toDelete = append(toDelete, pubkeyFilename)
		_, err = fmt.Fprintf(f, "%x\n", pubkey)
		if err2 := f.Close(); err == nil {
			err = err2
		}
		if err != nil {
			return err
		}
	}

	// All good, allow the written files to remain.
	toDelete = nil

	if privkeyFilename != "" {
		fmt.Printf("privkey written to %s\n", privkeyFilename)
	} else {
		fmt.Printf("privkey %x\n", privkey)
	}
	if pubkeyFilename != "" {
		fmt.Printf("pubkey  written to %s\n", pubkeyFilename)
	} else {
		fmt.Printf("pubkey  %x\n", pubkey)
	}

	return nil
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
	var genKey bool
	var configPath string

	flag.StringVar(&udpAddr, "addr", "[::]:53", "UDP address to listen on")
	flag.StringVar(&domain, "domain", "", "base domain in requests")
	flag.StringVar(&apiUrl, "api-endpoint", "https://registration.refraction.network/api/register", "API endpoint to use when performing API registration")
	flag.StringVar(&bdApiUrl, "bdapi-endpoint", "https://registration.refraction.network/api/register-bidirectional", "API endpoint to use when performing API registration")
	flag.StringVar(&privkeyPath, "privkey", "", "server private key filename")
	flag.StringVar(&pubkeyFilenameOut, "pubkeyfilename", "", "generated server public key filename (only used with -genKey)")
	flag.StringVar(&privkeyFilenameOut, "privkeyfilename", "", "generated server private key filename (only used with -genKey)")
	flag.BoolVar(&genKey, "genkey", false, "generate a server keypair; print to stdout or save to files")
	flag.StringVar(&configPath, "config", "", "configuration file path")
	flag.Parse()

	if genKey {
		if err := generateKeypair(privkeyFilenameOut, pubkeyFilenameOut); err != nil {
			fmt.Fprintf(os.Stderr, "cannot generate keypair: %v\n", err)
			os.Exit(2)
		}
		return
	}

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
	}

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

	log.SetFlags(log.LstdFlags | log.LUTC)

	privkey, err := readKeyFromFile(privkeyPath)
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
