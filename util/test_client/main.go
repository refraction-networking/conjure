package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/gotapdance/tapdance"
)

const (
	defaultAPIEndpoint     = "https://registration.refraction.network/api/register"
	defaultBDAPIEndpoint   = "https://registration.refraction.network/api/register-bidirectional"
	defaultConnectionDelay = 750 * time.Millisecond

	testCovertAddr = "http://1.1.1.1:80/"
)

var defaultGenFilter = func(uint32) bool { return true }

var availableGens = map[uint32]string{
	// 957:  "assets/ClientConf.957",
	1159: "assets/ClientConf.1159",
	1163: "assets/ClientConf.1163",
	1164: "assets/ClientConf.1164",
}

type connCfg struct {
	registrar
	transport
	disableOverrides bool
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
		logger().Info("no connection configs to run")
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

func (c *connCfg) ToRunners(availableGens map[uint32]string, availableVersions []string) ([]*connCfgRunner, error) {
	runners := []*connCfgRunner{}
	for gen := range availableGens {
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

		dialer := &tapdance.Dialer{
			DarkDecoy:                 true,
			DarkDecoyRegistrar:        c.registrar.Registrar,
			TransportConfig:           c.transport.Transport,
			DisableRegistrarOverrides: c.disableOverrides,
		}

		runner := &connCfgRunner{
			connCfg:    c,
			ClientConf: conf,
			dialer:     dialer,
		}
		runners = append(runners, runner)

	}

	return runners, nil
}

func (c *connCfg) String() string {
	return fmt.Sprintf("%s", c.Transport.Name())
}

func buildConnectionConfigs(transports []transport, registrars []registrar) ([]*connCfg, error) {
	logger().Debug("building configs", "transports", len(transports), "registrars", len(registrars))
	connectionConfigs := []*connCfg{}
	for _, transport := range transports {
		for _, registrar := range registrars {
			for _, b := range []bool{true, false} {
				config := &connCfg{
					registrar:        registrar,
					transport:        transport,
					disableOverrides: b,
				}
				connectionConfigs = append(connectionConfigs, config)
			}
		}
	}
	return connectionConfigs, nil
}

type connCfgRunner struct {
	dialer

	*connCfg
	*pb.ClientConf
}

func (c *connCfgRunner) String() string {
	return fmt.Sprintf("%d %s %t", c.ClientConf.GetGeneration(), c.Transport.Name(), c.dialer.(*tapdance.Dialer).DisableRegistrarOverrides)
}

// Run is NOT thread safe
func (c *connCfgRunner) Run() error {

	logger().Debug("running", "config", c.String())

	// set the clientconf in the singleton Assets() without overwriting the existing one on disk
	err := tapdance.Assets().SetClientConf(c.ClientConf, false)
	if err != nil {
		return err
	}

	return testRunnerHTTPGet(c)
}

func testRunnerHTTPGet(c *connCfgRunner) error {
	httpTransport := http.Transport{
		DialContext: c.DialContext,
	}
	httpClient := &http.Client{
		Transport: &httpTransport,
		Timeout:   10 * time.Second,
	}

	resp, err := httpClient.Get(testCovertAddr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	logger().Debug("response", "status", resp.Status, "headers", resp.Header)
	return nil
}

func testRunnerEcho(c *connCfgRunner) error {
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	conn, err := c.DialContext(ctx, "tcp", testCovertAddr)
	if err != nil {
		return err
	}

	byteLen := 5120
	r := make([]byte, byteLen)
	_, err = rand.Read(r)
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

func main() {
	logger().Info("Testing Conjure Client Variants")
	// setLogLevel(slog.LevelDebug)
	setLogLevel(levelTrace)

	connectionConfigs, err := collectConnectionConfigs()
	if err != nil {
		panic(err)
	}

	nTrials := 2
	for config := range connectionConfigs {
		errors := map[string]error{}
		runs := 0
		for i := 0; i < nTrials; i++ {
			runners, err := config.ToRunners(availableGens, availableVersions)
			if err != nil {
				logger().Error("failed to create runners from %s: %w", config, err)
			}
			for _, runner := range runners {
				if err := runner.Run(); err != nil {
					errors[runner.String()] = err
				}
				runs++
			}
		}

		logger().Info("Result", "config", config, fmt.Sprintf("%d/%d", runs-len(errors), runs))
		for cfg, e := range errors {
			logger().Debug("connection failed", "config", cfg, "error", e)
		}
	}
}
