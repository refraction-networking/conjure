package lib

import (
	"fmt"
	"os"
	"strconv"

	toml "github.com/pelletier/go-toml"
)

// ConjurePhantomSubnet - Weighted option to choose phantom address from.
type ConjurePhantomSubnet struct {
	Weight  uint32
	Subnets []string
}

// SubnetConfig - Configuration of subnets for Conjure to choose a Phantom out of.
type SubnetConfig struct {
	WeightedSubnets []ConjurePhantomSubnet
}

// PhantomIPSelector - Object for tracking current generation to SubnetConfig Mapping.
type PhantomIPSelector struct {
	Networks map[uint]*SubnetConfig
}

// type shim because github.com/pelletier/go-toml doesn't allow for integer value keys to maps so
// we have to parse them ourselves. :(
type phantomIPSelectorInternal struct {
	Networks map[string]*SubnetConfig
}

// GetPhantomSubnetSelector gets the location of the configuration file from an
// environment variable and returns the parsed configuration.
func GetPhantomSubnetSelector() (*PhantomIPSelector, error) {
	return SubnetsFromTomlFile(os.Getenv("PHANTOM_SUBNET_LOCATION"))
}

// SubnetsFromTomlFile takes a path and parses the toml config file
func SubnetsFromTomlFile(path string) (*PhantomIPSelector, error) {

	tree, err := toml.LoadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error opening configuration file: %v", err)
	}

	var pss = &PhantomIPSelector{
		Networks: make(map[uint]*SubnetConfig),
	}
	// shim because github.com/pelletier/go-toml doesn't allow for integer value keys to maps so
	// we have to parse them ourselves. :(
	var phantomSelectorSet = &phantomIPSelectorInternal{}
	err = tree.Unmarshal(phantomSelectorSet)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling configuration file: %v", err)
	}

	for gen, set := range phantomSelectorSet.Networks {
		g, err := strconv.Atoi(gen)
		if err != nil {
			return nil, err
		}
		// fmt.Printf("[GetPhantomSubnetSelector] adding %d, %+v\n", g, set)
		pss.AddGeneration(g, set)
	}

	return pss, nil
}
