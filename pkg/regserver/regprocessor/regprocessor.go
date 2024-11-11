package regprocessor

/*
#include <zmq.h>
*/
import "C"

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	mrand "math/rand"
	"net"
	"sync"
	"time"

	zmq "github.com/pebbe/zmq4"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/metrics"
	"github.com/refraction-networking/conjure/pkg/phantoms"
	"github.com/refraction-networking/conjure/pkg/regserver/overrides"
	"github.com/refraction-networking/conjure/pkg/station/lib"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/prefix"

	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

var (
	ErrNoC2SBody = errors.New("no C2S body")

	// ErrNilC2S       = errors.New("C2S is nil")

	ErrSharedSecret = errors.New("shared secret undefined or insufficient length")

	// ErrSelectIP     = errors.New("failed to select IP")
	// ErrGenSharedKey = errors.New("failed to generate shared key")

	ErrZmqSocket   = errors.New("failed to create zmq socket")
	ErrZmqAuthFail = errors.New("failed to set up auth on zmq socket")
	// ErrRegPubFailed = errors.New("failed to publish to registration")

	ErrRegProcessFailed = errors.New("failed to process registration")

	ErrZmqFault = zmq.Errno(C.EINVAL)
	// ErrZmqAccess        = zmq.Errno(C.EACCES)
)

const (
	// RegIDLen The length of the shared secret sent by the client in bytes.
	RegIDLen = 16

	// SecretLength gives the length of a secret (used for minimum registration body len)
	SecretLength = 32
)

type zmqSender interface {
	SendBytes([]byte, zmq.Flag) (int, error)
	Close() error
}

type ipSelector interface {
	Select([]byte, uint, uint, bool) (*phantoms.PhantomIP, error)
}

// RegProcessor provides an interface to publish registrations and helper functions to process registration requests
type RegProcessor struct {
	zmqMutex      sync.Mutex
	selectorMutex sync.RWMutex
	ipSelector    ipSelector
	sock          zmqSender
	metrics       *metrics.Metrics
	authenticated bool
	privkey       []byte // private key for the zmq_privkey pair - for signing proto messages to stations.

	regOverrides interfaces.Overrides

	transports map[pb.TransportType]lib.Transport

	enforceSubnetOverrides                 bool
	minOverrideSubnets                     []Subnet
	minOverrideSubnetsCumulativeWeights    []float64
	prefixOverrideSubnetsCumulativeWeights []float64
	prefixOverrideSubnets                  []Subnet
	exclusionsFromOverride                 []Subnet
	prcntMinConnsToOverride                float64
	prcntPrefixConnsToOverride             float64
}

type Subnet struct {
	CIDR      Ipnet           `toml:"cidr"`
	Weight    float64         `toml:"weight"`
	Port      uint32          `toml:"port"`
	Transport string          `toml:"transport"`
	PrefixId  prefix.PrefixID `toml:"prefix_id"`
}

type Ipnet struct {
	*net.IPNet
}

// UnmarshalText makes CIDR compatible with TOML decoding
func (n *Ipnet) UnmarshalText(text []byte) error {
	_, cidr, err := net.ParseCIDR(string(text))
	if err != nil {
		return err
	}
	n.IPNet = cidr
	return nil
}

// helper function to convert IPv4 to uint32
func ipv4ToUint32(ip net.IP) (uint32, error) {
	err := errors.New("Provided IP is not IPv4")
	if ip == nil {
		return 0, err
	}

	ip = ip.To4()
	if ip == nil {
		return 0, err
	}

	return binary.BigEndian.Uint32(ip), nil
}

// helper function to cenvert uint32 to IPv4
func uint32ToIPv4(ip *uint32) net.IP {
	if ip == nil {
		return nil
	}

	ipInt := *ip
	return net.IPv4(
		byte(ipInt>>24),
		byte(ipInt>>16),
		byte(ipInt>>8),
		byte(ipInt),
	)
}

// helper function that wraps randomInt()
func getRandUint32IPv4(ipNet *net.IPNet) (uint32, error) {
	ipUint32, err := ipv4ToUint32(ipNet.IP)
	if err != nil {
		return 0, errors.New("Failed to convert IPv4 to uint32")
	}

	mask := ipNet.Mask
	ones, bits := mask.Size()
	hosts := uint32(1 << uint32(bits-ones))

	ip, err := randomInt(ipUint32, ipUint32+hosts)
	if err != nil {
		return 0, errors.New("Failed to get random IPv4 as uint32 from the given range")
	}
	return ip, nil
}

// helper function to get random integers within a range
func randomInt(x, y uint32) (uint32, error) {
	rangeSize := y - x
	// Generate a random number in the range [0, rangeSize)
	randomNum, err := rand.Int(rand.Reader, big.NewInt(int64(rangeSize)))
	if err != nil {
		return 0, err
	}
	// Return the random number in the range [x, y]
	return x + uint32(randomNum.Int64()), nil
}

// helper function to override the prefix in the registration response
func overridePrefix(newRegResp *pb.RegistrationResponse, prefixId prefix.PrefixID, dstPort uint32) error {
	// Override Phantom dstPort
	newRegResp.DstPort = proto.Uint32(dstPort)
	// Override Prefix choice and PrefixParam
	newPrefix, err := prefix.TryFromID(prefixId)
	var fp = newPrefix.FlushPolicy()
	var i int32 = int32(newPrefix.ID())
	newparams := &pb.PrefixTransportParams{}
	newparams.PrefixId = &i
	newparams.CustomFlushPolicy = &fp
	newparams.Prefix = newPrefix.Bytes()
	anypbParams, err := anypb.New(newparams)
	if err != nil {
		return err
	}
	newRegResp.TransportParams = anypbParams
	return nil
}

// helper function to validate override percentages for the Min and Prefix transports set by reg_config.toml
func validateOverridePercentages(prcntMinConnsToOverride float64, prcntPrefixConnsToOverride float64) (float64, float64) {
	if prcntMinConnsToOverride > 100.0 || prcntMinConnsToOverride < 0.0 {
		fmt.Println("prcnt_min_conns_to_override value in reg_config.toml is out of range [0,100]. Resetting to 50%")
		prcntMinConnsToOverride = 50 * 10
	} else {
		prcntMinConnsToOverride = math.Round(prcntMinConnsToOverride*100) / 10
	}
	if prcntPrefixConnsToOverride > 100.0 || prcntPrefixConnsToOverride < 0.0 {
		fmt.Println("prcnt_prefix_conns_to_override value in reg_config.toml is out of range [0,100]. Resetting to 50%")
		prcntPrefixConnsToOverride = 50 * 10
	} else {
		prcntPrefixConnsToOverride = math.Round(prcntPrefixConnsToOverride*100) / 10
	}
	return prcntMinConnsToOverride, prcntPrefixConnsToOverride
}

// shallow-copy the override subnets into different slices based on transport type.
// could be improved to handle different transports
func splitOverrideSubnets(overrideSubnets []Subnet) ([]Subnet, []Subnet) {

	var minOverrideSubnets []Subnet
	var prefixOverrideSubnets []Subnet
	for _, subnet := range overrideSubnets {
		if subnet.Transport == "Min_Transport" {
			minOverrideSubnets = append(minOverrideSubnets, subnet)
		} else if subnet.Transport == "Prefix_Transport" {
			prefixOverrideSubnets = append(prefixOverrideSubnets, subnet)
		}
	}
	return minOverrideSubnets, prefixOverrideSubnets
}

// calculate cumulative weights for a given subnets slice
func processOverrideSubnetsWeights(subnets []Subnet) []float64 {

	if len(subnets) == 0 {
		return nil
	}

	var totalWeight float64
	for _, subnet := range subnets {
		totalWeight += subnet.Weight
	}

	cumulativeWeights := make([]float64, len(subnets))
	for i, subnet := range subnets {
		if i == 0 {
			cumulativeWeights[i] = subnet.Weight / totalWeight
		} else {
			cumulativeWeights[i] = cumulativeWeights[i-1] + (subnet.Weight / totalWeight)
		}
	}
	return cumulativeWeights
}

// NewRegProcessor initialize a new RegProcessor
func NewRegProcessor(zmqBindAddr string, zmqPort uint16, privkey []byte, authVerbose bool, stationPublicKeys []string, metrics *metrics.Metrics, enforceSubnetOverrides bool, overrideSubnets []Subnet, exclusionsFromOverride []Subnet, prcntMinConnsToOverride float64, prcntPrefixConnsToOverride float64) (*RegProcessor, error) {

	if len(privkey) != ed25519.PrivateKeySize {
		// We require the 64 byte [private_key][public_key] format to Sign using crypto/ed25519
		return nil, fmt.Errorf("incorrect private key size %d, expected %d", len(privkey), ed25519.PrivateKeySize)
	}

	phantomSelector, err := phantoms.GetPhantomSubnetSelector()
	if err != nil {
		return nil, err
	}

	regProcessor, err := newRegProcessor(zmqBindAddr, zmqPort, privkey, authVerbose, stationPublicKeys, enforceSubnetOverrides, overrideSubnets, exclusionsFromOverride, prcntMinConnsToOverride, prcntPrefixConnsToOverride)
	if err != nil {
		return nil, err
	}
	regProcessor.ipSelector = phantomSelector
	regProcessor.metrics = metrics

	return regProcessor, nil
}

// initializes the registration processor without the phantom selector which can be added by a
// wrapping function before it is returned. This function is required for testing.
func newRegProcessor(zmqBindAddr string, zmqPort uint16, privkey []byte, authVerbose bool, stationPublicKeys []string, enforceSubnetOverrides bool, overrideSubnets []Subnet, exclusionsFromOverride []Subnet, prcntMinConnsToOverride float64, prcntPrefixConnsToOverride float64) (*RegProcessor, error) {
	sock, err := zmq.NewSocket(zmq.PUB)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrZmqSocket, err)
	}

	// XXX: for some weird reason zmq takes just the private key portion of the keypair as the z85
	// encoded secret key. I guess for public key operations it is enough.
	privkeyZ85 := zmq.Z85encode(string(privkey[:32]))

	zmq.AuthSetVerbose(authVerbose)
	zmq.AuthAllow("*")
	zmq.AuthCurveAdd("*", stationPublicKeys...)

	// DO NOT REMOVE THIS LINE, this enables authentication for the zmq tunnels. If this requires
	// a change be sure to re-test that the keyed validation works how you expect it to.
	err = zmq.AuthStart()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrZmqAuthFail, err)
	}

	err = sock.ServerAuthCurve("*", privkeyZ85)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrZmqAuthFail, err)
	}

	err = sock.Bind(fmt.Sprintf("tcp://%s:%d", zmqBindAddr, zmqPort))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrZmqSocket, err)
	}

	var regOverrides interfaces.Overrides = nil
	if true { // TODO: update this with any desired registration overrides.
		regOverrides = interfaces.Overrides([]interfaces.RegOverride{overrides.NewRandPrefixOverride()})
	}

	prcntMinConnsToOverride, prcntPrefixConnsToOverride = validateOverridePercentages(prcntMinConnsToOverride, prcntPrefixConnsToOverride)

	minOverrideSubnets, prefixOverrideSubnets := splitOverrideSubnets(overrideSubnets)

	minOverrideSubnetsCumulativeWeights := processOverrideSubnetsWeights(minOverrideSubnets)
	prefixOverrideSubnetsCumulativeWeights := processOverrideSubnetsWeights(prefixOverrideSubnets)

	rp := &RegProcessor{
		zmqMutex:                               sync.Mutex{},
		selectorMutex:                          sync.RWMutex{},
		sock:                                   sock,
		transports:                             make(map[pb.TransportType]lib.Transport),
		authenticated:                          true,
		privkey:                                privkey,
		regOverrides:                           regOverrides,
		enforceSubnetOverrides:                 enforceSubnetOverrides,
		minOverrideSubnets:                     minOverrideSubnets,
		prefixOverrideSubnets:                  prefixOverrideSubnets,
		minOverrideSubnetsCumulativeWeights:    minOverrideSubnetsCumulativeWeights,
		prefixOverrideSubnetsCumulativeWeights: prefixOverrideSubnetsCumulativeWeights,
		exclusionsFromOverride:                 make([]Subnet, len(exclusionsFromOverride)),
		prcntMinConnsToOverride:                prcntMinConnsToOverride,
		prcntPrefixConnsToOverride:             prcntPrefixConnsToOverride,
	}
	copy(rp.exclusionsFromOverride, exclusionsFromOverride)

	return rp, nil
}

// NewRegProcessorNoAuth creates a regprocessor without authentication to zmq address
func NewRegProcessorNoAuth(zmqBindAddr string, zmqPort uint16, metrics *metrics.Metrics, enforceSubnetOverrides bool, overrideSubnets []Subnet, exclusionsFromOverride []Subnet, prcntMinConnsToOverride float64, prcntPrefixConnsToOverride float64) (*RegProcessor, error) {
	sock, err := zmq.NewSocket(zmq.PUB)
	if err != nil {
		return nil, ErrZmqSocket
	}

	err = sock.Bind(fmt.Sprintf("tcp://%s:%d", zmqBindAddr, zmqPort))
	if err != nil {
		return nil, ErrZmqSocket
	}

	phantomSelector, err := phantoms.GetPhantomSubnetSelector()
	if err != nil {
		return nil, err
	}

	prcntMinConnsToOverride, prcntPrefixConnsToOverride = validateOverridePercentages(prcntMinConnsToOverride, prcntPrefixConnsToOverride)

	minOverrideSubnets, prefixOverrideSubnets := splitOverrideSubnets(overrideSubnets)

	minOverrideSubnetsCumulativeWeights := processOverrideSubnetsWeights(minOverrideSubnets)
	prefixOverrideSubnetsCumulativeWeights := processOverrideSubnetsWeights(prefixOverrideSubnets)

	rp := &RegProcessor{
		zmqMutex:                               sync.Mutex{},
		selectorMutex:                          sync.RWMutex{},
		ipSelector:                             phantomSelector,
		sock:                                   sock,
		metrics:                                metrics,
		transports:                             make(map[pb.TransportType]lib.Transport),
		authenticated:                          false,
		enforceSubnetOverrides:                 enforceSubnetOverrides,
		minOverrideSubnets:                     minOverrideSubnets,
		prefixOverrideSubnets:                  prefixOverrideSubnets,
		minOverrideSubnetsCumulativeWeights:    minOverrideSubnetsCumulativeWeights,
		prefixOverrideSubnetsCumulativeWeights: prefixOverrideSubnetsCumulativeWeights,
		exclusionsFromOverride:                 make([]Subnet, len(exclusionsFromOverride)),
		prcntMinConnsToOverride:                prcntMinConnsToOverride,
		prcntPrefixConnsToOverride:             prcntPrefixConnsToOverride,
	}
	copy(rp.exclusionsFromOverride, exclusionsFromOverride)

	return rp, nil
}

// Close cleans up the (ZMQ) servers running in the background supporting registration.
func (p *RegProcessor) Close() error {
	if p.authenticated {
		zmq.AuthStop()
	}
	p.sock.Close()
	return nil
}

// AddTransport initializes a transport so that it can be tracked by the manager when
// clients register.
func (p *RegProcessor) AddTransport(index pb.TransportType, t lib.Transport) error {
	if p == nil {
		return fmt.Errorf("failed to add transport to uninitialized RegProcessor")
	}

	if p.transports == nil {
		p.transports = make(map[pb.TransportType]lib.Transport)
	}

	p.transports[index] = t
	return nil
}

// sendToZMQ sends registration message to zmq
func (p *RegProcessor) sendToZMQ(message []byte) error {
	p.zmqMutex.Lock()
	_, err := p.sock.SendBytes(message, zmq.DONTWAIT)
	p.zmqMutex.Unlock()

	return err
}

// RegisterUnidirectional process a unidirectional registration request and publish it to zmq
func (p *RegProcessor) RegisterUnidirectional(c2sPayload *pb.C2SWrapper, regMethod pb.RegistrationSource, clientAddr []byte) error {
	// While Registration response is a valid field in the client-to-station-wrapper (C2SWrapper) it
	// is not a field that the client is allowed to set, and it is not meaningful in the context of
	// a unidirectional registration.
	if c2sPayload.GetRegistrationResponse() != nil {
		c2sPayload.RegistrationResponse = nil
	}

	zmqPayload, err := p.processC2SWrapper(c2sPayload, clientAddr, regMethod)
	if err != nil {
		return err
	}

	err = p.sendToZMQ(zmqPayload)
	if err != nil {
		return ErrRegProcessFailed
	}

	return nil
}

// RegisterBidirectional process a bidirectional registration request, publish it to zmq, and returns a response
func (p *RegProcessor) RegisterBidirectional(c2sPayload *pb.C2SWrapper, regMethod pb.RegistrationSource, clientAddr []byte) (*pb.RegistrationResponse, error) {
	// While Registration response is a valid field in the client-to-station-wrapper (C2SWrapper) it
	// is not a field that the client is allowed to set, so we clear anything that is already here.
	if c2sPayload.GetRegistrationResponse() != nil {
		c2sPayload.RegistrationResponse = nil
	}

	regResp, err := p.processBdReq(c2sPayload)
	if err != nil {
		return nil, err
	}

	zmqPayload, err := p.processC2SWrapper(c2sPayload, clientAddr, regMethod)
	if err != nil {
		return nil, err
	}

	err = p.sendToZMQ(zmqPayload)
	if err != nil {
		return nil, ErrRegProcessFailed
	}

	return regResp, nil

}

// processBdReq reads a bidirectional request, generates phantom IPs, and returns a registration response for the client that has the ip filled out
func (p *RegProcessor) processBdReq(c2sPayload *pb.C2SWrapper) (*pb.RegistrationResponse, error) {
	// Create registration response object
	regResp := &pb.RegistrationResponse{}

	c2s := c2sPayload.GetRegistrationPayload()
	if c2s == nil {
		return nil, ErrNoC2SBody
	}

	clientLibVer := uint(c2s.GetClientLibVersion())

	// Generate seed and phantom address
	cjkeys, err := core.GenSharedKeys(clientLibVer, c2sPayload.SharedSecret, c2s.GetTransport())
	if err != nil {
		// p.logger.Println("Failed to generate the shared key using SharedSecret:", err)
		return nil, ErrRegProcessFailed
	}

	phantomSubnetSupportsRandPort := true
	if c2s.GetV4Support() {
		p.selectorMutex.RLock()
		defer p.selectorMutex.RUnlock()
		phantom4, err := p.ipSelector.Select(
			cjkeys.ConjureSeed,
			uint(c2s.GetDecoyListGeneration()), //generation type uint
			clientLibVer,
			false,
		)

		if err != nil {
			return nil, err
		}

		addr4 := binary.BigEndian.Uint32(phantom4.To4())
		regResp.Ipv4Addr = &addr4
		phantomSubnetSupportsRandPort = phantom4.SupportRandomPort()
	}

	if c2s.GetV6Support() {
		p.selectorMutex.RLock()
		defer p.selectorMutex.RUnlock()
		phantom6, err := p.ipSelector.Select(
			cjkeys.ConjureSeed,
			uint(c2s.GetDecoyListGeneration()),
			clientLibVer,
			true,
		)
		if err != nil {
			return nil, err
		}

		regResp.Ipv6Addr = *phantom6.IP()
		phantomSubnetSupportsRandPort = phantomSubnetSupportsRandPort && phantom6.SupportRandomPort()
	}

	transportType := c2s.GetTransport()
	transportParams := c2s.GetTransportParams()
	t, ok := p.transports[transportType]
	if !ok {
		return nil, fmt.Errorf("unknown transport")
	}

	params, err := t.ParseParams(uint(c2s.GetClientLibVersion()), transportParams)
	if err != nil {
		return nil, fmt.Errorf("failed to parse transport parameters: %w", err)
	}

	// Overrides will modify the C2SWrapper and put the updated registrationResponse inside to be
	// forwarded to the station.
	c2sPayload.RegistrationResponse = regResp
	if p.regOverrides != nil && !c2s.GetDisableRegistrarOverrides() {
		err := p.regOverrides.Override(c2sPayload, rand.Reader)
		if err != nil {
			return nil, err
		}
		regResp = c2sPayload.GetRegistrationResponse()
	} else {
		regResp.TransportParams = nil
		if c2sPayload.RegistrationResponse != nil {
			c2sPayload.RegistrationResponse.TransportParams = nil
		}
		regResp = c2sPayload.GetRegistrationResponse()
	}

	if phantomSubnetSupportsRandPort {
		dstPort, err := t.GetDstPort(uint(c2s.GetClientLibVersion()), cjkeys.ConjureSeed, params)
		if err != nil {
			return nil, fmt.Errorf("error determining destination port: %w", err)
		}

		// we have to cast to uint32 because protobuf using varint for all int / uint types and doesn't
		// have an outward facing uint16 type.
		regResp.DstPort = proto.Uint32(uint32(dstPort))
	} else {
		regResp.DstPort = proto.Uint32(443)
	}
	if p.enforceSubnetOverrides {
		ipv4FromRegResponse := uint32ToIPv4(regResp.Ipv4Addr)
		for _, subnet := range p.exclusionsFromOverride {
			// TODO: apply exclusions based on both transport and subnet
			if subnet.CIDR.IPNet.Contains(ipv4FromRegResponse) {
				// the IPv4 originally chosen by the client exists in a subnet we excluded from overrides
				// so do not apply overrides
				return regResp, nil
			}
		}

		num, err := randomInt(0, 10000)
		if err != nil {
			// In case of an error, return the original regResp and
			// do not apply overrides
			return regResp, nil
		}

		// random float64 between 0 and 999
		randNumFloat := float64(num) / 10.0

		var ipNet *net.IPNet
		var dstPortOverride uint32

		// random float64 between 0 and 1
		mrand.Seed(time.Now().UnixNano())
		randVal := mrand.Float64()

		// ignore prior choices and begin experimental overrides for Min and Prefix transports only
		if transportType == pb.TransportType_Min {
			if randNumFloat < p.prcntMinConnsToOverride {
				if p.minOverrideSubnets == nil {
					// reg_conf.toml does not contain subnet overrides for Min transport
					return regResp, nil
				}

				for i, cumulativeWeight := range p.minOverrideSubnetsCumulativeWeights {
					if randVal < cumulativeWeight {
						ipNet = p.minOverrideSubnets[i].CIDR.IPNet
						//dstPortOverride = p.minOverrideSubnets[i].Port
					}
				}

				if ipNet == nil {
					// problem in choosing a weighted override subnet
					// so do not apply overrides
					return regResp, nil
				}

				ip, err := getRandUint32IPv4(ipNet)
				if err != nil {
					// failed to get random IPv4 as uint32 from the given range.
					// do not apply override and return the original regResp.
					return regResp, nil
				}
				regResp.Ipv4Addr = proto.Uint32(ip)
			}
		} else if transportType == pb.TransportType_Prefix {

			// Override the Phantom IPv4 for clients with the Prefix transport
			// and override the transport type only if c2s.GetDisableRegistrarOverrides() is false
			if !c2s.GetDisableRegistrarOverrides() {
				if randNumFloat < p.prcntPrefixConnsToOverride {
					if p.prefixOverrideSubnets == nil {
						// reg_conf.toml does not contain subnet overrides for Prefix transport
						return regResp, nil
					}

					//newRegResp := &pb.RegistrationResponse{}
					var prefixid prefix.PrefixID
					for i, cumulativeWeight := range p.prefixOverrideSubnetsCumulativeWeights {
						if randVal < cumulativeWeight {
							ipNet = p.prefixOverrideSubnets[i].CIDR.IPNet
							dstPortOverride = p.prefixOverrideSubnets[i].Port
							prefixid = p.prefixOverrideSubnets[i].PrefixId
						}
					}

					if ipNet == nil {
						// problem in choosing a weighted override subnet
						// so do not apply overrides
						return regResp, nil
					}

					ip, err := getRandUint32IPv4(ipNet)
					if err != nil {
						// failed to get random IPv4 as uint32 from the given range.
						// do not apply override and return the original regResp.
						return regResp, nil
					}

					newRegResp := proto.Clone(regResp).(*pb.RegistrationResponse)

					err = overridePrefix(newRegResp, prefixid, dstPortOverride)
					if err != nil {
						return regResp, nil
					}
					newRegResp.Ipv4Addr = proto.Uint32(ip)

					regResp = newRegResp
					c2sPayload.RegistrationResponse = regResp
				}
			}
		}
	}
	return regResp, nil
}

// processC2SWrapper adds missing variables to the input c2s and returns the payload in format ready to be published to zmq
func (p *RegProcessor) processC2SWrapper(c2sPayload *pb.C2SWrapper, clientAddr []byte, regMethod pb.RegistrationSource) ([]byte, error) {
	if c2sPayload == nil {
		return nil, ErrNoC2SBody
	}

	if len(c2sPayload.GetSharedSecret()) < RegIDLen/2 {
		return nil, ErrSharedSecret
	}

	p.metrics.Add("reg_processed_"+regMethod.String(), 1)

	payload := &pb.C2SWrapper{}

	// If the channel that the registration was received over was not specified
	// in the C2SWrapper set it here as the source.
	if c2sPayload.GetRegistrationSource() == pb.RegistrationSource_Unspecified {
		source := regMethod
		payload.RegistrationSource = &source
	} else {
		source := c2sPayload.GetRegistrationSource()
		payload.RegistrationSource = &source
	}

	// If the address that the registration was received from was NOT set in the
	// C2SWrapper set it here to the source address of the request.
	if (c2sPayload.GetRegistrationAddress() == nil ||
		c2sPayload.GetRegistrationSource() == regMethod) && clientAddr != nil {
		payload.RegistrationAddress = clientAddr
	} else {
		payload.RegistrationAddress = c2sPayload.GetRegistrationAddress()
	}

	if p.authenticated && c2sPayload.GetRegistrationResponse() != nil {
		regRespBytes, err := proto.Marshal(c2sPayload.GetRegistrationResponse())
		if err != nil {
			return nil, err
		}
		// Sign the bytes for the marshalled Registration response with the registration server's
		// ed25519 key so that the stations will know that the registration response with parameter
		// overrides was approved by the registrar (not sent by the client).
		payload.RegRespBytes = regRespBytes
		payload.RegRespSignature = ed25519.Sign(p.privkey, regRespBytes)
	}

	payload.SharedSecret = c2sPayload.GetSharedSecret()
	payload.RegistrationPayload = c2sPayload.GetRegistrationPayload()
	payload.RegistrationResponse = c2sPayload.GetRegistrationResponse()

	return proto.Marshal(payload)
}

// ReloadSubnets allows the registrar to reload the configuration for phantom address selection
// subnets when the registrar receives a SIGHUP signal for example. If it fails it reports and error
// and keeps the existing set of phantom subnets.
func (p *RegProcessor) ReloadSubnets() error {
	phantomSelector, err := phantoms.GetPhantomSubnetSelector()
	if err != nil {
		return err
	}

	p.selectorMutex.Lock()
	defer p.selectorMutex.Unlock()
	p.ipSelector = phantomSelector

	return nil
}

// ReloadOverrides allows the registrar to reload the configuration for the registration processing
// overrides when the registrar receives a SIGHUP signal for example.
// TODO: implement
func (p *RegProcessor) ReloadOverrides() error {
	return nil
}
