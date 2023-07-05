package phantoms

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"

	pb "github.com/refraction-networking/conjure/proto"
	"golang.org/x/crypto/hkdf"
)

type Choice struct {
	Subnets []string
	Weight  int64
}

// getSubnets - return EITHER all subnet strings as one composite array if we are
//
//	selecting unweighted, or return the array associated with the (seed) selected
//	array of subnet strings based on the associated weights
func getSubnets(sc *pb.PhantomSubnetsList, seed []byte, weighted bool) []string {

	var out []string = []string{}

	if weighted {

		weightedSubnets := sc.GetWeightedSubnets()
		if weightedSubnets == nil {
			return []string{}
		}

		choices := make([]Choice, 0, len(weightedSubnets))

		totWeight := int64(0)
		for _, cjSubnet := range weightedSubnets {
			weight := cjSubnet.GetWeight()
			subnets := cjSubnet.GetSubnets()
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

		weightedSubnets := sc.GetWeightedSubnets()
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

// SubnetFilter - Filter IP subnets based on whatever to prevent specific subnets from
//
//	inclusion in choice. See v4Only and v6Only for reference.
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

// SelectAddrFromSubnetOffset given a CIDR block and offset, return the net.IP
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

// selectIPAddr selects an ip address from the list of subnets associated
// with the specified generation by constructing a set of start and end values
// for the high and low values in each allocation. The random number is then
// bound between the global min and max of that set. This ensures that
// addresses are chosen based on the number of addresses in the subnet.
func selectIPAddr(seed []byte, subnets []*net.IPNet) (*net.IP, error) {
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
	return &result, nil
}

// SelectPhantom - select one phantom IP address based on shared secret
func SelectPhantom(seed []byte, subnetsList *pb.PhantomSubnetsList, transform SubnetFilter, weighted bool) (*net.IP, error) {

	s, err := parseSubnets(getSubnets(subnetsList, seed, weighted))
	if err != nil {
		return nil, fmt.Errorf("failed to parse subnets: %v", err)
	}

	if transform != nil {
		s, err = transform(s)
		if err != nil {
			return nil, err
		}
	}

	return selectIPAddr(seed, s)
}

// SelectPhantomUnweighted - select one phantom IP address based on shared secret
func SelectPhantomUnweighted(seed []byte, subnets *pb.PhantomSubnetsList, transform SubnetFilter) (*net.IP, error) {
	return SelectPhantom(seed, subnets, transform, false)
}

// SelectPhantomWeighted - select one phantom IP address based on shared secret
func SelectPhantomWeighted(seed []byte, subnets *pb.PhantomSubnetsList, transform SubnetFilter) (*net.IP, error) {
	return SelectPhantom(seed, subnets, transform, true)
}

// GetDefaultPhantomSubnets implements the
func GetDefaultPhantomSubnets() *pb.PhantomSubnetsList {
	var w1 = uint32(9.0)
	var w2 = uint32(1.0)
	return &pb.PhantomSubnetsList{
		WeightedSubnets: []*pb.PhantomSubnets{
			{
				Weight:  &w1,
				Subnets: []string{"192.122.190.0/24", "2001:48a8:687f:1::/64"},
			},
			{
				Weight:  &w2,
				Subnets: []string{"141.219.0.0/16", "35.8.0.0/16"},
			},
		},
	}
}

// Just returns the list of subnets provided by the protobuf.
// Convenience function to not have to export getSubnets() or parseSubnets()
func GetUnweightedSubnetList(subnetsList *pb.PhantomSubnetsList) ([]*net.IPNet, error) {
	return parseSubnets(getSubnets(subnetsList, nil, false))
}
