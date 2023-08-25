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

type phantomNet struct {
	*net.IPNet
	supportRandomPort bool
}

func (p *phantomNet) SupportRandomPort() bool {
	return p.supportRandomPort
}

// getSubnets - return EITHER all subnet strings as one composite array if we are
//
//	selecting unweighted, or return the array associated with the (seed) selected
//	array of subnet strings based on the associated weights
func getSubnets(sc *pb.PhantomSubnetsList, seed []byte, weighted bool) ([]*phantomNet, error) {
	weightedSubnets := sc.GetWeightedSubnets()
	if weightedSubnets == nil {
		return []*phantomNet{}, nil
	}

	if weighted {
		choices := make([]*pb.PhantomSubnets, 0, len(weightedSubnets))

		totWeight := int64(0)
		for _, cjSubnet := range weightedSubnets {
			weight := cjSubnet.GetWeight()
			subnets := cjSubnet.GetSubnets()
			if subnets == nil {
				continue
			}

			totWeight += int64(weight)
			choices = append(choices, cjSubnet)
		}

		// Sort choices assending
		sort.Slice(choices, func(i, j int) bool {
			return choices[i].GetWeight() < choices[j].GetWeight()
		})

		// Naive method: get random int, subtract from weights until you are < 0
		hkdfReader := hkdf.New(sha256.New, seed, nil, []byte("phantom-select-subnet"))
		totWeightBig := big.NewInt(totWeight)
		rndBig, err := rand.Int(hkdfReader, totWeightBig)
		if err != nil {
			return nil, err
		}

		// Decrement rnd by each weight until it's < 0
		rnd := rndBig.Int64()
		for _, choice := range choices {
			rnd -= int64(choice.GetWeight())
			if rnd < 0 {
				return parseSubnets(choice)
			}
		}

		return []*phantomNet{}, nil
	}

	// Use unweighted config for subnets, concat all into one array and return.
	out := []*phantomNet{}
	for _, cjSubnet := range weightedSubnets {
		nets, err := parseSubnets(cjSubnet)
		if err != nil {
			return nil, fmt.Errorf("error parsing subnet: %v", err)
		}
		out = append(out, nets...)
	}

	return out, nil
}

// SubnetFilter - Filter IP subnets based on whatever to prevent specific subnets from
//
//	inclusion in choice. See v4Only and v6Only for reference.
type SubnetFilter func([]*phantomNet) ([]*phantomNet, error)

// V4Only - a functor for transforming the subnet list to only include IPv4 subnets
func V4Only(obj []*phantomNet) ([]*phantomNet, error) {
	out := []*phantomNet{}

	for _, _net := range obj {
		if ipv4net := _net.IP.To4(); ipv4net != nil {
			out = append(out, _net)
		}
	}
	return out, nil
}

// V6Only - a functor for transforming the subnet list to only include IPv6 subnets
func V6Only(obj []*phantomNet) ([]*phantomNet, error) {
	out := []*phantomNet{}

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

func parseSubnets(phantomSubnet *pb.PhantomSubnets) ([]*phantomNet, error) {
	subnets := []*phantomNet{}

	if len(phantomSubnet.GetSubnets()) == 0 {
		return nil, fmt.Errorf("parseSubnets - no subnets provided")
	}

	for _, strNet := range phantomSubnet.GetSubnets() {
		parsedNet, err := parseSubnet(strNet)
		if err != nil {
			return nil, err
		}

		subnets = append(subnets, &phantomNet{IPNet: parsedNet, supportRandomPort: phantomSubnet.GetRandomizeDstPort()})
	}

	return subnets, nil
}

func parseSubnet(phantomSubnet string) (*net.IPNet, error) {
	_, parsedNet, err := net.ParseCIDR(phantomSubnet)
	if err != nil {
		return nil, err
	}
	if parsedNet == nil {
		return nil, fmt.Errorf("failed to parse %v as subnet", parsedNet)
	}

	return parsedNet, nil
}

// SelectAddrFromSubnetOffset given a CIDR block and offset, return the net.IP
func SelectAddrFromSubnetOffset(net1 *phantomNet, offset *big.Int) (*PhantomIP, error) {
	bits, addrLen := net1.Mask.Size()

	// Compute network size (e.g. an ipv4 /24 is 2^(32-24)
	var netSize big.Int
	netSize.Exp(big.NewInt(2), big.NewInt(int64(addrLen-bits)), nil)

	// Check that offset is within this subnet
	if netSize.Cmp(offset) <= 0 {
		return nil, errors.New("offset too big for subnet")
	}

	ipBigInt := &big.Int{}
	if v4net := net1.IP.To4(); v4net != nil {
		ipBigInt.SetBytes(net1.IP.To4())
	} else if v6net := net1.IP.To16(); v6net != nil {
		ipBigInt.SetBytes(net1.IP.To16())
	}

	ipBigInt.Add(ipBigInt, offset)
	ip := net.IP(ipBigInt.Bytes())

	return &PhantomIP{ip: &ip, supportRandomPort: net1.supportRandomPort}, nil
}

// selectIPAddr selects an ip address from the list of subnets associated
// with the specified generation by constructing a set of start and end values
// for the high and low values in each allocation. The random number is then
// bound between the global min and max of that set. This ensures that
// addresses are chosen based on the number of addresses in the subnet.
func selectIPAddr(seed []byte, subnets []*phantomNet) (*PhantomIP, error) {
	type idNet struct {
		min, max big.Int
		net      *phantomNet
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
			_idNet.net = _net
			idNets = append(idNets, _idNet)
		} else if ipv6net := _net.IP.To16(); ipv6net != nil {
			_idNet := idNet{}
			_idNet.min.Set(addressTotal)
			addressTotal.Add(addressTotal, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(128-netMaskOnes)), nil))
			_idNet.max.Sub(addressTotal, big.NewInt(1))
			_idNet.net = _net
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
	var result *PhantomIP
	for _, _idNet := range idNets {
		// fmt.Printf("tot:%s, seed%%tot:%s     id cmp max: %d,  id cmp min: %d %s\n", addressTotal.String(), id, _idNet.max.Cmp(id), _idNet.min.Cmp(id), _idNet.net.String())
		if _idNet.max.Cmp(id) >= 0 && _idNet.min.Cmp(id) <= 0 {

			var offset big.Int
			offset.Sub(id, &_idNet.min)
			result, err = SelectAddrFromSubnetOffset(_idNet.net, &offset)
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

// SelectPhantom - select one phantom IP address based on shared secret
func SelectPhantom(seed []byte, subnetsList *pb.PhantomSubnetsList, transform SubnetFilter, weighted bool) (*PhantomIP, error) {

	s, err := getSubnets(subnetsList, seed, weighted)
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
func SelectPhantomUnweighted(seed []byte, subnets *pb.PhantomSubnetsList, transform SubnetFilter) (*PhantomIP, error) {
	return SelectPhantom(seed, subnets, transform, false)
}

// SelectPhantomWeighted - select one phantom IP address based on shared secret
func SelectPhantomWeighted(seed []byte, subnets *pb.PhantomSubnetsList, transform SubnetFilter) (*PhantomIP, error) {
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

// GetUnweightedSubnetList returns the list of subnets provided by the protobuf. Convenience
// function to not have to export getSubnets() or parseSubnets()
func GetUnweightedSubnetList(subnetsList *pb.PhantomSubnetsList) ([]*phantomNet, error) {
	return getSubnets(subnetsList, nil, false)
}

// type aliase to make embedding unexported
// nolint:unused
type ip = net.IP
type PhantomIP struct {
	*ip
	supportRandomPort bool
}

func (p *PhantomIP) SupportRandomPort() bool {
	return p.supportRandomPort
}

func (p *PhantomIP) IP() *net.IP {
	return p.ip
}
