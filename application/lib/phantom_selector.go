package lib

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"sort"

	wr "github.com/mroth/weightedrand"
	"golang.org/x/crypto/hkdf"
)

const (
	phantomSelectionMinGeneration uint = 1
	phantomHkdfMinVersion         uint = 2
)

// getSubnetsVarint - return EITHER all subnet strings as one composite array if
// we are selecting unweighted, or return the array associated with the (seed)
// selected array of subnet strings based on the associated weights
//
// Used by Client version 0 and 1
func (sc *SubnetConfig) getSubnetsVarint(seed []byte, weighted bool) []string {

	var out []string = []string{}

	if weighted {
		// seed random with hkdf derived seed provided by client
		seedInt, n := binary.Varint(seed)
		if n == 0 {
			fmt.Println("failed to seed random for weighted rand")
			return nil
		}
		mrand.Seed(seedInt)

		choices := make([]wr.Choice, 0, len(sc.WeightedSubnets))
		for _, cjSubnet := range sc.WeightedSubnets {
			choices = append(choices, wr.Choice{Item: cjSubnet.Subnets, Weight: uint(cjSubnet.Weight)})
		}
		c, err := wr.NewChooser(choices...)
		if err != nil {
			return out
		}

		out = c.Pick().([]string)
	} else {

		// Use unweighted config for subnets, concat all into one array and return.
		for _, cjSubnet := range sc.WeightedSubnets {
			out = append(out, cjSubnet.Subnets...)
		}
	}

	return out
}

// getSubnetsHkdf returns EITHER all subnet strings as one composite array if
// we are selecting unweighted, or return the array associated with the (seed)
// selected array of subnet strings based on the associated weights. Random
// values are seeded using an hkdf function to prevent biases introduced by
// math/rand and varint.
//
// Used by Client version 2+
func (sc *SubnetConfig) getSubnetsHkdf(seed []byte, weighted bool) []string {

	type Choice struct {
		Subnets []string
		Weight  int64
	}

	var out []string = []string{}

	if weighted {

		weightedSubnets := sc.WeightedSubnets
		if weightedSubnets == nil {
			return []string{}
		}

		choices := make([]Choice, 0, len(weightedSubnets))

		totWeight := int64(0)
		for _, cjSubnet := range weightedSubnets {
			weight := cjSubnet.Weight
			subnets := cjSubnet.Subnets
			if subnets == nil {
				continue
			}

			totWeight += int64(weight)
			choices = append(choices, Choice{Subnets: subnets, Weight: int64(weight)})
		}

		// Sort choices assending
		sort.Slice(choices, func(i, j int) bool {
			return choices[i].Weight < choices[j].Weight
		})

		// Naive method: get random int, subtract from weights until you are < 0
		hkdfReader := hkdf.New(sha256.New, seed, nil, []byte("phantom-select-subnet"))
		totWeightBig := big.NewInt(totWeight)
		rndBig, err := rand.Int(hkdfReader, totWeightBig)
		if err != nil {
			return nil
		}

		// Decrement rnd by each weight until it's < 0
		rnd := rndBig.Int64()
		for _, choice := range choices {
			rnd -= choice.Weight
			if rnd < 0 {
				return choice.Subnets
			}
		}

	} else {

		weightedSubnets := sc.WeightedSubnets
		if weightedSubnets == nil {
			return []string{}
		}

		// Use unweighted config for subnets, concat all into one array and return.
		for _, cjSubnet := range weightedSubnets {
			out = append(out, cjSubnet.Subnets...)
		}
	}

	return out
}

// SubnetFilter - Filter IP subnets based on whatever to prevent specific
// subnets from inclusion in choice. See v4Only and v6Only for reference.
type SubnetFilter func([]*net.IPNet) ([]*net.IPNet, error)

// V4Only - a functor for transforming the subnet list to only include IPv4 subnets
func V4Only(obj []*net.IPNet) ([]*net.IPNet, error) {
	var out []*net.IPNet = []*net.IPNet{}

	for _, _net := range obj {
		if ipv4net := _net.IP.To4(); ipv4net != nil {
			out = append(out, _net)
		}
	}
	return out, nil
}

// V6Only - a functor for transforming the subnet list to only include IPv6 subnets
func V6Only(obj []*net.IPNet) ([]*net.IPNet, error) {
	var out []*net.IPNet = []*net.IPNet{}

	for _, _net := range obj {
		if _net.IP == nil {
			continue
		}
		if net := _net.IP.To4(); net != nil {
			continue
		}
		out = append(out, _net)
	}
	return out, nil
}

func parseSubnets(phantomSubnets []string) ([]*net.IPNet, error) {
	var subnets []*net.IPNet = []*net.IPNet{}

	if len(phantomSubnets) == 0 {
		return nil, fmt.Errorf("parseSubnets - no subnets provided")
	}

	for _, strNet := range phantomSubnets {
		_, parsedNet, err := net.ParseCIDR(strNet)
		if err != nil {
			return nil, err
		}
		if parsedNet == nil {
			return nil, fmt.Errorf("failed to parse %v as subnet", parsedNet)
		}

		subnets = append(subnets, parsedNet)
	}

	return subnets, nil
	// return nil, fmt.Errorf("parseSubnets not implemented yet")
}

// NewPhantomIPSelector - create object currently populated with a static map of
// generation number to SubnetConfig, but this may be loaded dynamically in the
// future.
func NewPhantomIPSelector() (*PhantomIPSelector, error) {
	return GetPhantomSubnetSelector()
}

// Select - select an ip address from the list of subnets associated with the specified generation
func (p *PhantomIPSelector) Select(seed []byte, generation uint, clientLibVer uint, v6Support bool) (net.IP, error) {

	genConfig := p.GetSubnetsByGeneration(generation)
	if genConfig == nil {
		return nil, fmt.Errorf("generation number not recognized")
	}

	var genSubnetStrings []string
	if clientLibVer < phantomHkdfMinVersion {
		// Version 0 or 1
		genSubnetStrings = genConfig.getSubnetsVarint(seed, true)
	} else {
		// Version 2
		genSubnetStrings = genConfig.getSubnetsHkdf(seed, true)
	}

	genSubnets, err := parseSubnets(genSubnetStrings)
	if err != nil {
		return nil, err
	}

	if !v6Support {
		genSubnets, err = V4Only(genSubnets)
		if err != nil {
			return nil, err
		}
	}

	// handle legacy clientLibVersions for selecting phantoms.
	if clientLibVer < phantomSelectionMinGeneration {
		// Version 0
		return selectPhantomImplV0(seed, genSubnets)
	} else if clientLibVer < phantomHkdfMinVersion {
		// Version 1
		return selectPhantomImplVarint(seed, genSubnets)
	}

	// Version 2+
	return selectPhantomImplHkdf(seed, genSubnets)
}

// selectPhantomImplVarint - select an ip address from the list of subnets
// associated with the specified generation by constructing a set of start and
// end values for the high and low values in each allocation. The random number
// is then bound between the global min and max of that set. This ensures that
// addresses are chosen based on the number of addresses in the subnet.
func selectPhantomImplVarint(seed []byte, subnets []*net.IPNet) (net.IP, error) {
	type idNet struct {
		min, max big.Int
		net      net.IPNet
	}
	var idNets []idNet

	// Compose a list of ID Nets with min, max and network associated and count
	// the total number of available addresses.
	addressTotal := big.NewInt(0)
	for _, _net := range subnets {
		netMaskOnes, _ := _net.Mask.Size()
		if ipv4net := _net.IP.To4(); ipv4net != nil {
			_idNet := idNet{}
			_idNet.min.Set(addressTotal)
			addressTotal.Add(addressTotal, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(32-netMaskOnes)), nil))
			_idNet.max.Sub(addressTotal, big.NewInt(1))
			_idNet.net = *_net
			idNets = append(idNets, _idNet)
		} else if ipv6net := _net.IP.To16(); ipv6net != nil {
			_idNet := idNet{}
			_idNet.min.Set(addressTotal)
			addressTotal.Add(addressTotal, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(128-netMaskOnes)), nil))
			_idNet.max.Sub(addressTotal, big.NewInt(1))
			_idNet.net = *_net
			idNets = append(idNets, _idNet)
		} else {
			return nil, fmt.Errorf("failed to parse %v", _net)
		}
	}

	// If the total number of addresses is 0 something has gone wrong
	if addressTotal.Cmp(big.NewInt(0)) <= 0 {
		return nil, fmt.Errorf("no valid addresses specified")
	}

	// Pick a value using the seed in the range of between 0 and the total
	// number of addresses.
	id := &big.Int{}
	id.SetBytes(seed)
	if id.Cmp(addressTotal) >= 0 {
		id.Mod(id, addressTotal)
	}

	// Find the network (ID net) that contains our random value and select a
	// random address from that subnet.
	// min >= id%total >= max
	var result net.IP
	var err error
	for _, _idNet := range idNets {
		// fmt.Printf("tot:%s, seed%%tot:%s     id cmp max: %d,  id cmp min: %d %s\n", addressTotal.String(), id, _idNet.max.Cmp(id), _idNet.min.Cmp(id), _idNet.net.String())
		if _idNet.max.Cmp(id) >= 0 && _idNet.min.Cmp(id) <= 0 {
			result, err = SelectAddrFromSubnet(seed, &_idNet.net)
			if err != nil {
				return nil, fmt.Errorf("failed to chose IP address: %v", err)
			}
		}
	}

	// We want to make it so this CANNOT happen
	if result == nil {
		return nil, errors.New("nil result should not be possible")
	}
	return result, nil
}

// selectPhantomImplV0 implements support for the legacy (buggy) client phantom
// address selection algorithm.
func selectPhantomImplV0(seed []byte, subnets []*net.IPNet) (net.IP, error) {

	addressTotal := big.NewInt(0)

	type idNet struct {
		min, max big.Int
		net      *net.IPNet
	}
	var idNets []idNet

	for _, _net := range subnets {
		netMaskOnes, _ := _net.Mask.Size()
		if ipv4net := _net.IP.To4(); ipv4net != nil {
			_idNet := idNet{}
			_idNet.min.Set(addressTotal)
			addressTotal.Add(addressTotal, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(32-netMaskOnes)), nil))
			addressTotal.Sub(addressTotal, big.NewInt(1))
			_idNet.max.Set(addressTotal)
			_idNet.net = _net
			idNets = append(idNets, _idNet)
		} else if ipv6net := _net.IP.To16(); ipv6net != nil {
			_idNet := idNet{}
			_idNet.min.Set(addressTotal)
			addressTotal.Add(addressTotal, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(128-netMaskOnes)), nil))
			addressTotal.Sub(addressTotal, big.NewInt(1))
			_idNet.max.Set(addressTotal)
			_idNet.net = _net
			idNets = append(idNets, _idNet)
		} else {
			return nil, fmt.Errorf("failed to parse %v", _net)
		}
	}

	if addressTotal.Cmp(big.NewInt(0)) <= 0 {
		return nil, fmt.Errorf("no valid addresses specified")
	}

	id := &big.Int{}
	id.SetBytes(seed)
	if id.Cmp(addressTotal) > 0 {
		id.Mod(id, addressTotal)
	}

	var result net.IP
	var err error
	for _, _idNet := range idNets {
		if _idNet.max.Cmp(id) >= 0 && _idNet.min.Cmp(id) == -1 {
			result, err = SelectAddrFromSubnet(seed, _idNet.net)
			if err != nil {
				return nil, fmt.Errorf("failed to chose IP address: %v", err)
			}
		}
	}
	if result == nil {
		return nil, errors.New("let's rewrite the phantom address selector")
	}
	return result, nil
}

// SelectAddrFromSubnet - given a seed and a CIDR block choose an address.
//
// This is done by generating a seeded random bytes up to teh length of the full
// address then using the net mask to zero out any bytes that are already
// specified by the CIDR block. Tde masked random value is then added to the
// cidr block base giving the final randomly selected address.
func SelectAddrFromSubnet(seed []byte, net1 *net.IPNet) (net.IP, error) {
	bits, addrLen := net1.Mask.Size()

	ipBigInt := &big.Int{}
	if v4net := net1.IP.To4(); v4net != nil {
		ipBigInt.SetBytes(net1.IP.To4())
	} else if v6net := net1.IP.To16(); v6net != nil {
		ipBigInt.SetBytes(net1.IP.To16())
	}

	seedInt, n := binary.Varint(seed)
	if n == 0 {
		return nil, fmt.Errorf("failed to create seed ")
	}

	mrand.Seed(seedInt)
	randBytes := make([]byte, addrLen/8)
	_, err := mrand.Read(randBytes)
	if err != nil {
		return nil, err
	}
	randBigInt := &big.Int{}
	randBigInt.SetBytes(randBytes)

	mask := make([]byte, addrLen/8)
	for i := 0; i < addrLen/8; i++ {
		mask[i] = 0xff
	}
	maskBigInt := &big.Int{}
	maskBigInt.SetBytes(mask)
	maskBigInt.Rsh(maskBigInt, uint(bits))

	randBigInt.And(randBigInt, maskBigInt)
	ipBigInt.Add(ipBigInt, randBigInt)

	return net.IP(ipBigInt.Bytes()), nil
}

// SelectAddrFromSubnetOffset given a CIDR block and offset, return the net.IP
//
// Version 2: HKDF-based
func SelectAddrFromSubnetOffset(net1 *net.IPNet, offset *big.Int) (net.IP, error) {
	bits, addrLen := net1.Mask.Size()

	// Compute network size (e.g. an ipv4 /24 is 2^(32-24)
	var netSize big.Int
	netSize.Exp(big.NewInt(2), big.NewInt(int64(addrLen-bits)), nil)

	// Check that offset is within this subnet
	if netSize.Cmp(offset) <= 0 {
		return nil, errors.New("Offset too big for subnet")
	}

	ipBigInt := &big.Int{}
	if v4net := net1.IP.To4(); v4net != nil {
		ipBigInt.SetBytes(net1.IP.To4())
	} else if v6net := net1.IP.To16(); v6net != nil {
		ipBigInt.SetBytes(net1.IP.To16())
	}

	ipBigInt.Add(ipBigInt, offset)

	return net.IP(ipBigInt.Bytes()), nil
}

// selectPhantomImplHkdf selects an ip address from the list of subnets
// associated with the specified generation by constructing a set of start and
// end values for the high and low values in each allocation. The random number
// is then bound between the global min and max of that set. This ensures that
// addresses are chosen based on the number of addresses in the subnet.
func selectPhantomImplHkdf(seed []byte, subnets []*net.IPNet) (net.IP, error) {
	type idNet struct {
		min, max big.Int
		net      net.IPNet
	}
	var idNets []idNet

	// Compose a list of ID Nets with min, max and network associated and count
	// the total number of available addresses.
	addressTotal := big.NewInt(0)
	for _, _net := range subnets {
		netMaskOnes, _ := _net.Mask.Size()
		if ipv4net := _net.IP.To4(); ipv4net != nil {
			_idNet := idNet{}
			_idNet.min.Set(addressTotal)
			addressTotal.Add(addressTotal, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(32-netMaskOnes)), nil))
			_idNet.max.Sub(addressTotal, big.NewInt(1))
			_idNet.net = *_net
			idNets = append(idNets, _idNet)
		} else if ipv6net := _net.IP.To16(); ipv6net != nil {
			_idNet := idNet{}
			_idNet.min.Set(addressTotal)
			addressTotal.Add(addressTotal, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(128-netMaskOnes)), nil))
			_idNet.max.Sub(addressTotal, big.NewInt(1))
			_idNet.net = *_net
			idNets = append(idNets, _idNet)
		} else {
			return nil, fmt.Errorf("failed to parse %v", _net)
		}
	}

	// If the total number of addresses is 0 something has gone wrong
	if addressTotal.Cmp(big.NewInt(0)) <= 0 {
		return nil, fmt.Errorf("no valid addresses specified")
	}

	// Pick a value using the seed in the range of between 0 and the total
	// number of addresses.
	hkdfReader := hkdf.New(sha256.New, seed, nil, []byte("phantom-addr-id"))
	id, err := rand.Int(hkdfReader, addressTotal)
	if err != nil {
		return nil, err
	}

	// Find the network (ID net) that contains our random value and select a
	// random address from that subnet.
	// min >= id%total >= max
	var result net.IP
	for _, _idNet := range idNets {
		// fmt.Printf("tot:%s, seed%%tot:%s     id cmp max: %d,  id cmp min: %d %s\n", addressTotal.String(), id, _idNet.max.Cmp(id), _idNet.min.Cmp(id), _idNet.net.String())
		if _idNet.max.Cmp(id) >= 0 && _idNet.min.Cmp(id) <= 0 {

			var offset big.Int
			offset.Sub(id, &_idNet.min)
			result, err = SelectAddrFromSubnetOffset(&_idNet.net, &offset)
			if err != nil {
				return nil, fmt.Errorf("failed to chose IP address: %v", err)
			}
		}
	}

	// We want to make it so this CANNOT happen
	if result == nil {
		return nil, errors.New("nil result should not be possible")
	}
	return result, nil
}

// GetSubnetsByGeneration - provide a generation index. If the generation exists
// the associated SubnetConfig is returned. If it is not defined the default
// subnets are returned.
func (p *PhantomIPSelector) GetSubnetsByGeneration(generation uint) *SubnetConfig {
	if subnets, ok := p.Networks[generation]; ok {
		return subnets
	}

	// No Default subnets provided if the generation is not known
	return nil
}

// AddGeneration - add a subnet config as a new new generation, if the requested
// generation index is taken then it uses (and returns) the next available
// number.
func (p *PhantomIPSelector) AddGeneration(gen int, subnets *SubnetConfig) uint {

	ugen := uint(gen)

	if gen == -1 || p.IsTakenGeneration(ugen) {
		ugen = p.newGenerationIndex()
	}

	p.Networks[ugen] = subnets
	return ugen
}

func (p *PhantomIPSelector) newGenerationIndex() uint {
	maxGen := uint(0)
	for k := range p.Networks {
		if k > maxGen {
			maxGen = k
		}
	}
	return maxGen + 1
}

// IsTakenGeneration - check if the generation index is already in use.
func (p *PhantomIPSelector) IsTakenGeneration(gen uint) bool {
	if _, ok := p.Networks[gen]; ok {
		return true
	}
	return false
}

// RemoveGeneration - remove a generation from the mapping
func (p *PhantomIPSelector) RemoveGeneration(generation uint) bool {
	p.Networks[generation] = nil
	return true
}

// UpdateGeneration - Update the subnet list associated with a specific generation
func (p *PhantomIPSelector) UpdateGeneration(generation uint, subnets *SubnetConfig) bool {
	p.Networks[generation] = subnets
	return true
}
