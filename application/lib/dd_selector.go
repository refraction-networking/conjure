package lib

import (
	"errors"
	"fmt"
	"math/big"
	"net"
)

type DDIpSelector struct {
	Networks map[uint][]*net.IPNet
}

func defaultSubnets() []*net.IPNet {
	defaultSubnets := []string{"192.122.190.0/24", "2001:48a8:687f:1::/64"}
	return subnetListFromStrList(defaultSubnets)
}

func getStaticSubnets() map[uint][]*net.IPNet {
	nets := map[uint][]string{
		1: []string{"192.122.190.0/24", "2001:48a8:687f:1::/64"},
		2: []string{"192.122.190.0/28", "2001:48a8:687f:1::/96"},
	}

	networks := make(map[uint][]*net.IPNet)

	for gen, subnets := range nets {
		networks[gen] = subnetListFromStrList(subnets)
	}

	return networks
}

func NewDDIpSelector() (*DDIpSelector, error) {
	dd := DDIpSelector{
		Networks: getStaticSubnets(),
	}

	return &dd, nil
}

func (d *DDIpSelector) Select(seed []byte, generation uint, v6Support bool) (*net.IP, error) {
	addresses_total := big.NewInt(0)

	type idNet struct {
		min, max big.Int
		net      net.IPNet
	}
	var idNets []idNet

	genSubnets := d.GetSubnetsByGeneration(generation)

	for _, _net := range genSubnets {
		netMaskOnes, _ := _net.Mask.Size()
		if ipv4net := _net.IP.To4(); ipv4net != nil {
			_idNet := idNet{}
			_idNet.min.Set(addresses_total)
			addresses_total.Add(addresses_total, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(32-netMaskOnes)), nil))
			addresses_total.Sub(addresses_total, big.NewInt(1))
			_idNet.max.Set(addresses_total)
			_idNet.net = *_net
			idNets = append(idNets, _idNet)
		} else if ipv6net := _net.IP.To16(); ipv6net != nil {
			if v6Support {
				_idNet := idNet{}
				_idNet.min.Set(addresses_total)
				addresses_total.Add(addresses_total, big.NewInt(2).Exp(big.NewInt(2), big.NewInt(int64(128-netMaskOnes)), nil))
				addresses_total.Sub(addresses_total, big.NewInt(1))
				_idNet.max.Set(addresses_total)
				_idNet.net = *_net
				idNets = append(idNets, _idNet)
			}
		} else {
			return nil, fmt.Errorf("failed to parse %v", _net)
		}
	}
	id := &big.Int{}
	id.SetBytes(seed)
	if id.Cmp(addresses_total) > 0 {
		id.Mod(id, addresses_total)
	}
	if id.Cmp(addresses_total) == 0 {
		return nil, fmt.Errorf("No valid addresses to select from")
	}

	var result net.IP
	for _, _idNet := range idNets {
		if _idNet.max.Cmp(id) >= 0 && _idNet.min.Cmp(id) == -1 {
			if ipv4net := _idNet.net.IP.To4(); ipv4net != nil {
				ipBigInt := &big.Int{}
				ipBigInt.SetBytes(ipv4net)
				ipNetDiff := _idNet.max.Sub(id, &_idNet.min)
				ipBigInt.Add(ipBigInt, ipNetDiff)
				result = net.IP(ipBigInt.Bytes()).To4() // implicit check that it fits
			} else if ipv6net := _idNet.net.IP.To16(); ipv6net != nil {
				ipBigInt := &big.Int{}
				ipBigInt.SetBytes(ipv6net)
				ipNetDiff := _idNet.max.Sub(id, &_idNet.min)
				ipBigInt.Add(ipBigInt, ipNetDiff)
				result = net.IP(ipBigInt.Bytes()).To16()
			} else {
				return nil, fmt.Errorf("failed to parse %v", _idNet.net.IP)
			}
		}
	}
	if result == nil {
		return nil, errors.New("let's rewrite dark decoy selector")
	}
	return &result, nil
}

func (d *DDIpSelector) GetSubnetsByGeneration(generation uint) []*net.IPNet {
	if subnets, ok := d.Networks[generation]; ok {
		return subnets
	} else {
		return defaultSubnets()
	}
}

func (d *DDIpSelector) AddGeneration(gen int, subnets []string) uint {

	ugen := uint(gen)

	if gen == -1 || d.IsTakenGeneration(ugen) {
		ugen = d.newGenerationIndex()
	}

	d.Networks[ugen] = subnetListFromStrList(subnets)
	return ugen
}

func (d *DDIpSelector) newGenerationIndex() uint {
	maxGen := uint(0)
	for k := range d.Networks {
		if k > maxGen {
			maxGen = k
		}
	}
	return maxGen + 1
}

func (d *DDIpSelector) IsTakenGeneration(gen uint) bool {
	if _, ok := d.Networks[gen]; ok {
		return true
	}
	return false
}

func (d *DDIpSelector) RemoveGeneration(generation uint) bool {
	d.Networks[generation] = nil
	return true
}

func (d *DDIpSelector) UpdateGeneration(generation uint, subnets []string) bool {
	d.Networks[generation] = subnetListFromStrList(subnets)
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
