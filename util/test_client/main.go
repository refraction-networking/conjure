package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/gotapdance/tapdance"
)

const (
	defaultAPIEndpoint     = "https://registration.refraction.network/api/register"
	defaultBDAPIEndpoint   = "https://registration.refraction.network/api/register-bidirectional"
	defaultConnectionDelay = 750 * time.Millisecond

	testCovertAddr = "1.1.1.1:443"
)

var defaultGenFilter = func(uint32) bool { return true }

var availableGens = map[uint32]string{
	957:  "assets/ClientConf.957",
	1161: "assets/ClientConf.1161",
	1163: "assets/ClientConf.1163",
	1164: "assets/ClientConf.1164",
}

type connCfgRunner struct {
	tapdance.Registrar
	interfaces.Transport
	*pb.ClientConf
	dialer
}

func (c *connCfgRunner) String() string {
	return fmt.Sprintf("%s %s %d %s", c.Registrar, c.Transport.Name(), c.ClientConf.GetGeneration())
}

// Run is NOT thread safe
func (c *connCfgRunner) Run() error {
	// set the clientconf in the singleton Assets() without overwriting the existing one on disk
	err := tapdance.Assets().SetClientConf(c.ClientConf, false)
	if err != nil {
		return err
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := c.DialContext(ctx, "tcp", testCovertAddr)
	if err != nil {
		return err
	}

	return testConnection(conn)
}

func testConnection(conn net.Conn) error {
	byteLen := 5120
	r := make([]byte, byteLen)
	_, err := rand.Read(r)
	if err != nil {
		return err
	}
	n, err := conn.Write(r)
	if err != nil {
		return err
	} else if n != byteLen {
		return fmt.Errorf("failed to write all bytes: %d/%d", n, byteLen)
	}

	b := make([]byte, byteLen)
	n, err = io.ReadFull(conn, b)
	if err != nil {
		return fmt.Errorf("failed to read all bytes: %d/%d", n, byteLen)
	}

	return nil
}

type connCfg struct {
	registrar
	transport
	*pb.ClientConf
	disableOverrides  bool
	covert            string
	generations       []uint32
	clientLibVersions []uint32
}

func (c *connCfg) ToRunners(availableGens map[uint32]string, availableVersions []string) ([]*connCfgRunner, error) {
	runners := []*connCfgRunner{}
	for _, gen := range c.generations {
		if !c.transport.generationFilter(gen) || !c.registrar.generationFilter(gen) {
			continue
		}
		confPath, ok := availableGens[gen]
		if !ok {
			return nil, fmt.Errorf("no conf for generation %d", gen)
		}

		confReader, err := os.ReadFile(confPath)
		if err != nil {
			return nil, err
		}

		conf := &pb.ClientConf{}
		err = proto.Unmarshal(confReader, conf)
		if err != nil {
			return nil, err
		}

		for _, d := range availableDialers {
			runner := &connCfgRunner{
				Registrar:  c.registrar.Registrar,
				Transport:  c.transport.Transport,
				ClientConf: conf,
				dialer:     d,
			}
			runners = append(runners, runner)
		}
	}

	return runners, nil
}

func (c *connCfg) String() string {
	return fmt.Sprintf("%s %s %d", c.Registrar, c.Transport.Name(), c.ClientConf.GetGeneration())
}

func collectConnectionConfigs() (<-chan *connCfg, error) {
	connectionConfigs := []*connCfg{}

	// Transport Permutations
	transports := []transport{}
	transports = append(transports, prefixTransportPermutations()...)
	transports = append(transports, minTransportPermutations()...)
	transports = append(transports, obfs4TransportPermutations()...)
	transports = append(transports, dtlsTransportPermutations()...)

	// Registrar Permutations
	registrars := []registrar{}
	registrars = append(registrars, decoyRegistrarPermutations()...)
	registrars = append(registrars, dnsRegistrarPermutations()...)
	registrars = append(registrars, apiRegistrarPermutations()...)

	connectionConfigs, err := buildConnectionConfigs(transports, registrars)
	if err != nil {
		return nil, err
	} else if len(connectionConfigs) == 0 {
		fmt.Println("no connection configs to run")
		os.Exit(0)
	}

	configs := make(chan *connCfg)
	go func() {
		for _, config := range connectionConfigs {
			configs <- config
		}
		close(configs)
	}()
	return configs, nil
}

func buildConnectionConfigs(transports []transport, registrars []registrar) ([]*connCfg, error) {
	connectionConfigs := []*connCfg{}
	for _, transport := range transports {
		for _, registrar := range registrars {
			config := &connCfg{
				registrar:         registrar,
				transport:         transport,
				generations:       []uint32{},
				clientLibVersions: []uint32{},
			}
			connectionConfigs = append(connectionConfigs, config)
		}
	}
	return connectionConfigs, nil
}

func main() {
	fmt.Println("Testing Conjure Client Variants")

	n := 1
	connectionConfigs, err := collectConnectionConfigs()
	if err != nil {
		panic(err)
	}

	for config := range connectionConfigs {
		errors := map[string]error{}
		runs := 0
		for i := 0; i < n; i++ {
			runners, err := config.ToRunners(availableGens, availableVersions)
			if err != nil {
				slog.Error("failed to create runners from %s: %w", config, err)
			}
			for _, runner := range runners {
				if err := runner.Run(); err != nil {
					errors[runner.String()] = err
				}
				runs++
			}
		}

		fmt.Printf("%s %d/%d\n", config, runs-len(errors), runs)
		for cfg, e := range errors {
			slog.Debug("\t", cfg, e)
		}
	}
}

// func connectDirect(apiEndpoint string, registrar string, connectTarget string, localPort int, proxyHeader bool, v6Support bool, width int, t tapdance.Transport, disableOverrides bool, phantomNet string) error {
// 	if _, _, err := net.SplitHostPort(connectTarget); err != nil {
// 		return fmt.Errorf("failed to parse host and port from connectTarget %s: %v",
// 			connectTarget, err)

// 	}

// 	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort})
// 	if err != nil {
// 		return fmt.Errorf("error listening on port %v: %v", localPort, err)
// 	}

// 	dialer := tapdance.Dialer{
// 		DarkDecoy:          true,
// 		DarkDecoyRegistrar: registration.NewDecoyRegistrar(),
// 		UseProxyHeader:     proxyHeader,
// 		V6Support:          v6Support,
// 		Width:              width,
// 		RegDelay:           defaultConnectionDelay,
// 		// Transport:          getTransportFromName(transport), // Still works for backwards compatibility
// 		TransportConfig:           t,
// 		PhantomNet:                phantomNet,
// 		DisableRegistrarOverrides: disableOverrides,
// 	}

// 	switch registrar {
// 	case "decoy":
// 		dialer.DarkDecoyRegistrar = registration.NewDecoyRegistrar()
// 	case "api":
// 		if apiEndpoint == "" {
// 			apiEndpoint = defaultAPIEndpoint
// 		}
// 		dialer.DarkDecoyRegistrar, err = registration.NewAPIRegistrar(&registration.Config{
// 			Target:             apiEndpoint,
// 			Bidirectional:      false,
// 			MaxRetries:         3,
// 			SecondaryRegistrar: registration.NewDecoyRegistrar(),
// 		})
// 		if err != nil {
// 			return fmt.Errorf("error creating API registrar: %w", err)
// 		}
// 	case "bdapi":
// 		if apiEndpoint == "" {
// 			apiEndpoint = defaultBDAPIEndpoint
// 		}
// 		dialer.DarkDecoyRegistrar, err = registration.NewAPIRegistrar(&registration.Config{
// 			Target:             apiEndpoint,
// 			Bidirectional:      true,
// 			MaxRetries:         3,
// 			SecondaryRegistrar: registration.NewDecoyRegistrar(),
// 		})
// 		if err != nil {
// 			return fmt.Errorf("error creating API registrar: %w", err)
// 		}
// 	case "dns":
// 		dnsConf := tapdance.Assets().GetDNSRegConf()
// 		dialer.DarkDecoyRegistrar, err = newDNSRegistrarFromConf(dnsConf, false, 3, tapdance.Assets().GetConjurePubkey()[:])
// 		if err != nil {
// 			return fmt.Errorf("error creating DNS registrar: %w", err)
// 		}
// 	case "bddns":
// 		dnsConf := tapdance.Assets().GetDNSRegConf()
// 		dialer.DarkDecoyRegistrar, err = newDNSRegistrarFromConf(dnsConf, true, 3, tapdance.Assets().GetConjurePubkey()[:])
// 		if err != nil {
// 			return fmt.Errorf("error creating DNS registrar: %w", err)
// 		}
// 	default:
// 		return fmt.Errorf("unknown registrar %v", registrar)
// 	}

// 	for {
// 		clientConn, err := l.AcceptTCP()
// 		if err != nil {
// 			return fmt.Errorf("error accepting client connection %v: ", err)
// 		}

// 		go manageConn(dialer, connectTarget, clientConn)
// 	}
// }

// func manageConn(dialer tapdance.Dialer, connectTarget string, clientConn *net.TCPConn) {
// 	tdConn, err := dialer.Dial("tcp", connectTarget)
// 	if err != nil || tdConn == nil {
// 		fmt.Printf("failed to dial %s: %v\n", connectTarget, err)
// 		return
// 	}

// 	// Copy data from the client application into the DarkDecoy connection.
// 	// 		TODO: proper connection management with idle timeout
// 	var wg sync.WaitGroup
// 	wg.Add(2)
// 	go func() {
// 		io.Copy(tdConn, clientConn)
// 		wg.Done()
// 		tdConn.Close()
// 	}()
// 	go func() {
// 		io.Copy(clientConn, tdConn)
// 		wg.Done()
// 		clientConn.CloseWrite()
// 	}()
// 	wg.Wait()
// 	tapdance.Logger().Debug("copy loop ended")
// }
