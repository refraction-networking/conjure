package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pkg/profile"
	"github.com/refraction-networking/conjure"
	"github.com/refraction-networking/conjure/pkg/client/assets"
	"github.com/refraction-networking/conjure/pkg/log"
	"github.com/refraction-networking/conjure/pkg/phantoms"
	"github.com/refraction-networking/conjure/pkg/registrars/decoy-registrar"
	"github.com/refraction-networking/conjure/pkg/registrars/registration"
	transports "github.com/refraction-networking/conjure/pkg/transports/client"
	pb "github.com/refraction-networking/conjure/proto"
)

const (
	defaultAPIEndpoint     = "https://registration.refraction.network/api/register"
	defaultBDAPIEndpoint   = "https://registration.refraction.network/api/register-bidirectional"
	defaultConnectionDelay = 750 * time.Millisecond
)

func main() {
	defer profile.Start().Stop()

	var port = flag.Int("port", 10500, "TapDance will listen for connections on this port.")
	var excludeV6 = flag.Bool("disable-ipv6", false, "Explicitly disable IPv6 decoys. Default(false): enable IPv6 only if interface with global IPv6 address is available.")
	var proxyHeader = flag.Bool("proxy", false, "Send the proxy header with all packets from station to covert host")
	var decoy = flag.String("decoy", "", "Sets single decoy. ClientConf won't be requested. "+
		"Accepts \"SNI,IP\" or simply \"SNI\" — IP will be resolved. "+
		"Examples: \"site.io,1.2.3.4\", \"site.io\"")
	var assetsLocation = flag.String("assetsdir", "./assets/", "Folder to read assets from.")
	var width = flag.Uint("w", 5, "Number of registrations sent for each connection initiated")
	var debug = flag.Bool("debug", false, "Enable debug level logs")
	var trace = flag.Bool("trace", false, "Enable trace level logs")
	var connectTarget = flag.String("connect-addr", "", "If set, conjure will transparently connect to provided address, which must be either hostname:port or ip:port. "+
		"Default(unset): connects client to forwardproxy, to which CONNECT request is yet to be written.")

	var APIRegistration = flag.String("api-endpoint", "", "If set, API endpoint to use when performing API registration. Defaults to https://registration.refraction.network/api/register (or register-bidirectional for bdapi)")
	var registrar = flag.String("registrar", "decoy", "One of decoy, api, bdapi, dns, bddns.")
	var transport = flag.String("transport", "min", `The transport to use for Conjure connections. Current values include "prefix", "min" and "obfs4", "dtls".`)
	var randomizeDstPort = flag.Bool("rand-dst-port", true, `enable destination port randomization for the transport connection`)
	var prefixID = flag.Int("prefix-id", -1, "ID of the prefix to send, used with the `transport=\"prefix\"` option. Default is Random. See prefix transport for options")
	var disableOverrides = flag.Bool("disable-overrides", false, "Informs the registrar that chosen parameters will be used, only applicable to bidirectional reg methods")
	var phantomNet = flag.String("phantom", "", "Target phantom subnet. Must overlap with ClientConf, and will be achieved by brute force of seeds until satisfied")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Dark Decoy CLI\n$./cli -connect-addr=<decoy_address> [OPTIONS] \n\nOptions:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *connectTarget == "" {
		log.Errorf("dark decoys require -connect-addr to be set\n")
		flag.Usage()

		os.Exit(1)
	}

	v6Support := !*excludeV6

	_, err := conjure.AssetsSetDir(*assetsLocation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse assets: %s", err)
		os.Exit(1)
	}

	if *decoy != "" {
		err := setSingleDecoyHost(*decoy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to set single decoy host: %s\n", err)
			flag.Usage()
			os.Exit(255)
		}
	}

	// Check that the provided phantom net overlaps with at least one of our phatom options
	if *phantomNet != "" {
		// Load phantoms
		subnets, err := phantoms.GetUnweightedSubnetList(assets.Assets().GetPhantomSubnets())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get Phantom subnets: %v\n", err)
			os.Exit(255)
		}

		// Check that the provided phantom parses as a CIDR range
		_, phantomRange, err := net.ParseCIDR(*phantomNet)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing phantom subnet %s: %v\n", *phantomNet, err)
			flag.Usage()
			os.Exit(255)
		}

		// Iterate through all subnets, see if any overlap with the phantomRange
		found := false
		for _, subnet := range subnets {
			if subnet.Contains(phantomRange.IP) || phantomRange.Contains(subnet.IP) {
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "Error: provided phantom net %v does not overlap with any phantoms in ClientConf\n", *phantomNet)
			os.Exit(255)
		}
	}

	if *debug {
		log.SetLevel(log.DebugLevel)
		log.Debug("Debug logging enabled")
	}
	if *trace {
		log.SetLevel(log.TraceLevel)
		log.Trace("Trace logging enabled")
	}

	fmt.Printf("Using Station Pubkey: %s\n", hex.EncodeToString(conjure.GetPubkey()[:]))

	var params any
	var t conjure.Transport
	switch *transport {
	case "prefix":
		pID := int32(*prefixID)
		params = &pb.PrefixTransportParams{RandomizeDstPort: randomizeDstPort, PrefixId: &pID}
	default:
		params = &pb.GenericTransportParams{RandomizeDstPort: randomizeDstPort}
	}

	t, err = transports.NewWithParams(*transport, params)
	if err != nil {
		e := fmt.Errorf("error finding or creating transport %v: %v", *transport, err)
		log.Println(e)
		os.Exit(1)
	}

	err = connectDirect(*APIRegistration, *registrar, *connectTarget, *port, *proxyHeader, v6Support, *width, t, *disableOverrides, *phantomNet)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func connectDirect(apiEndpoint string, registrar string, connectTarget string, localPort int, proxyHeader bool, v6Support bool, width uint, t conjure.Transport, disableOverrides bool, phantomNet string) error {
	if _, _, err := net.SplitHostPort(connectTarget); err != nil {
		return fmt.Errorf("failed to parse host and port from connectTarget %s: %v",
			connectTarget, err)

	}

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort})
	if err != nil {
		return fmt.Errorf("error listening on port %v: %v", localPort, err)
	}

	dialer := conjure.Dialer{
		UseProxyHeader:            proxyHeader,
		IPSupport:                 v6Support,
		RegDelay:                  defaultConnectionDelay,
		Transport:                 t,
		PhantomNet:                phantomNet,
		DisableRegistrarOverrides: disableOverrides,
	}

	decoyRegistrar := decoy.NewDecoyRegistrar()
	decoyRegistrar.Width = width
	switch registrar {
	case "decoy":
		dialer.Registrar = decoyRegistrar
	case "api":
		if apiEndpoint == "" {
			apiEndpoint = defaultAPIEndpoint
		}
		dialer.Registrar, err = registration.NewAPIRegistrar(&registration.Config{
			Target:             apiEndpoint,
			Bidirectional:      false,
			MaxRetries:         3,
			SecondaryRegistrar: decoyRegistrar,
		})
		if err != nil {
			return fmt.Errorf("error creating API registrar: %w", err)
		}
	case "bdapi":
		if apiEndpoint == "" {
			apiEndpoint = defaultBDAPIEndpoint
		}
		dialer.Registrar, err = registration.NewAPIRegistrar(&registration.Config{
			Target:             apiEndpoint,
			Bidirectional:      true,
			MaxRetries:         3,
			SecondaryRegistrar: decoyRegistrar,
		})
		if err != nil {
			return fmt.Errorf("error creating API registrar: %w", err)
		}
	case "dns":
		dnsConf := conjure.Assets().GetDNSRegConf()
		dialer.Registrar, err = newDNSRegistrarFromConf(dnsConf, false, 3, conjure.Assets().GetPubkey()[:])
		if err != nil {
			return fmt.Errorf("error creating DNS registrar: %w", err)
		}
	case "bddns":
		dnsConf := conjure.Assets().GetDNSRegConf()
		dialer.Registrar, err = newDNSRegistrarFromConf(dnsConf, true, 3, conjure.Assets().GetPubkey()[:])
		if err != nil {
			return fmt.Errorf("error creating DNS registrar: %w", err)
		}
	default:
		return fmt.Errorf("unknown registrar %v", registrar)
	}

	for {
		clientConn, err := l.AcceptTCP()
		if err != nil {
			return fmt.Errorf("error accepting client connection %v: ", err)
		}

		go manageConn(dialer, connectTarget, clientConn)
	}
}

func manageConn(dialer conjure.Dialer, connectTarget string, clientConn *net.TCPConn) {
	tdConn, err := dialer.Dial("tcp", connectTarget)
	if err != nil || tdConn == nil {
		fmt.Printf("failed to dial %s: %v\n", connectTarget, err)
		return
	}

	// Copy data from the client application into the DarkDecoy connection.
	// 		TODO: proper connection management with idle timeout
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		io.Copy(tdConn, clientConn)
		wg.Done()
		tdConn.Close()
	}()
	go func() {
		io.Copy(clientConn, tdConn)
		wg.Done()
		clientConn.CloseWrite()
	}()
	wg.Wait()
	log.Debug("copy loop ended")
}

func setSingleDecoyHost(decoy string) error {
	splitDecoy := strings.Split(decoy, ",")

	var ip string
	switch len(splitDecoy) {
	case 1:
		ips, err := net.LookupHost(decoy)
		if err != nil {
			return err
		}
		ip = ips[0]
	case 2:
		ip = splitDecoy[1]
		if net.ParseIP(ip) == nil {
			return errors.New("provided IP address \"" + ip + "\" is invalid")
		}
	default:
		return errors.New("\"" + decoy + "\" contains too many commas")
	}

	sni := splitDecoy[0]

	decoySpec := pb.InitTLSDecoySpec(ip, sni)
	conjure.Assets().GetClientConfPtr().DecoyList =
		&pb.DecoyList{
			TlsDecoys: []*pb.TLSDecoySpec{
				decoySpec,
			},
		}
	maxUint32 := ^uint32(0) // max generation: station won't send ClientConf
	conjure.Assets().GetClientConfPtr().Generation = &maxUint32
	log.Infof("Single decoy parsed. SNI: %s, IP: %s", sni, ip)
	return nil
}

// NewDNSRegistrarFromConf creates a DNSRegistrar from DnsRegConf protobuf. Uses the pubkey in conf as default. If it is not supplied (nil), uses fallbackKey instead.
func newDNSRegistrarFromConf(conf *pb.DnsRegConf, bidirectional bool, maxTries int, fallbackKey []byte) (*registration.DNSRegistrar, error) {
	pubkey := conf.Pubkey
	if pubkey == nil {
		pubkey = fallbackKey
	}
	var method registration.DNSTransportMethodType
	switch *conf.DnsRegMethod {
	case pb.DnsRegMethod_UDP:
		method = registration.UDP
	case pb.DnsRegMethod_DOT:
		method = registration.DoT
	case pb.DnsRegMethod_DOH:
		method = registration.DoH
	default:
		return nil, errors.New("unknown reg method in conf")
	}

	return registration.NewDNSRegistrar(&registration.Config{
		DNSTransportMethod: method,
		Target:             *conf.Target,
		BaseDomain:         *conf.Domain,
		Pubkey:             pubkey,
		UTLSDistribution:   *conf.UtlsDistribution,
		MaxRetries:         maxTries,
		Bidirectional:      bidirectional,
		STUNAddr:           *conf.StunServer,
	})
}
