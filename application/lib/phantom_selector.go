package lib

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"net"

	wr "github.com/mroth/weightedrand"
)

// getSubnets - return EITHER all subnet strings as one composite array if we are
//		selecting unweighted, or return the array associated with the (seed) selected
//		array of subnet strings based on the associated weights
func (sc *SubnetConfig) getSubnets(seed []byte, weighted bool) []string {

	var out []string = []string{}

	if weighted {
		// seed random with hkdf derived seed provided by client
		seedInt, err := binary.ReadVarint(bytes.NewBuffer(seed))
		if err != nil {
			return nil
		}
		rand.Seed(seedInt)

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
			for _, subnet := range cjSubnet.Subnets {
				out = append(out, subnet)
			}
		}
	}

	return out
}

// SubnetFilter - Filter IP subnets based on whatever to prevent specific subnets from
//		inclusion in choice. See v4Only and v6Only for reference.
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

// NewPhantomIPSelector - create object currently populated with a static map of generation number
//		to SubnetConfig, but this may be loaded dynamically in the future.
func NewPhantomIPSelector() (*PhantomIPSelector, error) {
	return GetPhantomSubnetSelector()
}

// Select - select an ip address from the list of subnets associated with the specified generation
func (p *PhantomIPSelector) Select(seed []byte, generation uint, v6Support bool) (net.IP, error) {

	type idNet struct {
		min, max big.Int
		net      net.IPNet
	}
	var idNets []idNet

	genConfig := p.GetSubnetsByGeneration(generation)
	if genConfig == nil {
		return nil, fmt.Errorf("generation number not recognized")
	}

	genSubnetStrings := genConfig.getSubnets(seed, true)

	genSubnets, err := parseSubnets(genSubnetStrings)
	if err != nil {
		return nil, err
	}

	if v6Support == false {
		genSubnets, err = V4Only(genSubnets)
		if err != nil {
			return nil, err
		}
	}

	addressTotal := big.NewInt(0)
	for _, _net := range genSubnets {
		netMaskOnes, _ := _net.Mask.Size()
		if ipv4net := _net.IP.To4(); ipv4net != nil {
			_idNet := idNet{}
			_idNet.min.Set(addressTotal)
			addressTotal.Add(addressTotal, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(32-netMaskOnes)), nil))
			addressTotal.Sub(addressTotal, big.NewInt(1))
			_idNet.max.Set(addressTotal)
			_idNet.net = *_net
			idNets = append(idNets, _idNet)
		} else if ipv6net := _net.IP.To16(); ipv6net != nil {
			if v6Support {
				_idNet := idNet{}
				_idNet.min.Set(addressTotal)
				addressTotal.Add(addressTotal, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(128-netMaskOnes)), nil))
				addressTotal.Sub(addressTotal, big.NewInt(1))
				_idNet.max.Set(addressTotal)
				_idNet.net = *_net
				idNets = append(idNets, _idNet)
			}
		} else {
			return nil, fmt.Errorf("failed to parse %v", _net)
		}
	}
	id := &big.Int{}
	id.SetBytes(seed)
	if id.Cmp(addressTotal) > 0 {
		id.Mod(id, addressTotal)
	}
	if id.Cmp(addressTotal) == 0 {
		return nil, fmt.Errorf("No valid addresses to select from")
	}
	if addressTotal.Cmp(big.NewInt(0)) <= 0 {
		return nil, fmt.Errorf("No valid addresses specified")
	}

	var result net.IP
	for _, _idNet := range idNets {
		if _idNet.max.Cmp(id) >= 0 && _idNet.min.Cmp(id) == -1 {
			result, err = SelectAddrFromSubnet(seed, &_idNet.net)
			if err != nil {
				return nil, fmt.Errorf("Failed to chose IP address: %v", err)
			}
		}
	}
	if result == nil {
		return nil, errors.New("let's rewrite the phantom address selector")
	}
	return result, nil
}

// SelectAddrFromSubnet - given a seed and a CIDR block choose an address.
// 		This is done by generating a seeded random bytes up to the length of the
//		full address then using the net mask to zero out any bytes that are
//		already specified by the CIDR block. The masked random value is then
//		added to the cidr block base giving the final randomly selected address.
func SelectAddrFromSubnet(seed []byte, net1 *net.IPNet) (net.IP, error) {
	bits, addrLen := net1.Mask.Size()

	ipBigInt := &big.Int{}
	if v4net := net1.IP.To4(); v4net != nil {
		ipBigInt.SetBytes(net1.IP.To4())
	} else if v6net := net1.IP.To16(); v6net != nil {
		ipBigInt.SetBytes(net1.IP.To16())
	}

	seedInt, err := binary.ReadVarint(bytes.NewBuffer(seed))
	if err != nil {
		return nil, err
	}

	rand.Seed(seedInt)
	randBytes := make([]byte, addrLen/8)
	_, err = rand.Read(randBytes)
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

// GetSubnetsByGeneration - provide a generatio index. If the generation exists the associated
//		subnetconfig is returned. If it is not defined the default subnets are returned.
func (p *PhantomIPSelector) GetSubnetsByGeneration(generation uint) *SubnetConfig {
	if subnets, ok := p.Networks[generation]; ok {
		return subnets
	}

	// No Default subnets provided if the generation is not known
	return nil
}

// AddGeneration - add a subnet config as a new new generation, if the requested
//		generation index is taken then it uses (and returns) the next available number.
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

//UpdateGeneration - Update the subnet list associated with a specific generation
func (p *PhantomIPSelector) UpdateGeneration(generation uint, subnets *SubnetConfig) bool {
	p.Networks[generation] = subnets
	return true
}

func subnetListFromStrList(netStrs []string) []*net.IPNet {
	var subnets []*net.IPNet

	for gen, subnetStr := range netStrs {
		_, cidr, err := net.ParseCIDR(subnetStr)
		if err != nil || cidr == nil {
			fmt.Printf("failed to parse subnet \"%s\" for generation: %d", subnetStr, gen)
			continue
		}
		subnets = append(subnets, cidr)
	}
	return subnets
}
