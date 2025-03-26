package iface

import (
	"fmt"
	"net"
	"os"
)

var allocatedTuns = []string{}
var dnatAddr = ""
var dnatAddr6 = ""

// InitializeTunSet creates a tun set for conjure use including rules, tun interface, and associated custom
// tables. Do not call more than once in the same program without calling `TeardownTunSet` in-between
// (tracking interface names and addresses will break).
func InitializeTunSet(num int, prefix string, iface string) error {

	ex := &executor{}
	tableID := fmt.Sprintf("custom_%s", prefix)

	// sysctl setting to allow address spoofing
	_, err := ex.execute("sysctl", []string{"-w", "net.ipv4.conf.all.rp_filter=0"})
	if err != nil {
		return err
	}

	// Create custom table to handle DNAT lookups
	f, err := os.OpenFile("/etc/iproute2/rt_tables", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(fmt.Sprintf("200 %s", tableID)); err != nil {
		return err
	}

	err = createTunSet(num, prefix, iface, ex)
	if err != nil {
		TeardownTunSet(num, prefix)
	}

	return nil
}

// TeardownTunSet cleans up after a tun set, removes rules, tun interface, and associated custom tables
func TeardownTunSet(num int, prefix string) error {

	ex := &executor{}
	tableID := fmt.Sprintf("custom_%s", prefix)

	err := removeTunSet(num, prefix, ex)
	if err != nil {
		return err
	}

	// Remove custom table to handle DNAT lookups
	_, err = ex.execute("sed", []string{"-i", fmt.Sprintf("'/%s/d'", tableID), "/etc/iproute2/rt_tables"})
	if err != nil {
		return err
	}

	return nil
}

// createTunRule creates a tun rule by name and index
func createTunRule(id int, prefix string, ip4Addr string, ip6Addr string, exec Executor) error {

	if ip4Addr == "" && ip6Addr == "" {
		return fmt.Errorf("Must supply at least one address for tun interfaces")
	}

	tunID := fmt.Sprintf("tun_%s_%d", prefix, id)
	tableID := fmt.Sprintf("custom_%s", prefix)

	// Remove tun interface if it already exists
	_, err := exec.execute("ip", []string{"tuntap del mode tun", tunID})
	if err != nil {
		return err
	}

	// Create tun interface
	_, err = exec.execute("ip", []string{"tuntap add mode tun", tunID})
	if err != nil {
		return err
	}

	// Add reference to local lookup table
	_, err = exec.execute("ip", []string{"rule add iif", tunID, "lookup", tableID})
	if err != nil {
		return err
	}

	// Add reference to local lookup table
	_, err = exec.execute("ip", []string{"route add local 0.0.0.0/0 dev", tunID, "table", tableID})
	if err != nil {
		return err
	}

	// sysctl setting to allow address spoofing
	_, err = exec.execute("sysctl", []string{"-w", fmt.Sprintf("net.ipv4.conf.%s.rp_filter=0", tunID)})
	if err != nil {
		return err
	}

	if ip4Addr != "" {
		// Add DNAT rule
		_, err = exec.execute("iptables", []string{"-t nat -I PREROUTING 1 -p tcp -i", tunID, "-j DNAT --to", fmt.Sprintf("%v:41245", ip4Addr)})
		if err != nil {
			return err
		}

		// Accept traffic to be handled by the kernel on the tun interface
		_, err = exec.execute("iptables", []string{"-I INPUT 1 -i", tunID, "-j ACCEPT"})
		if err != nil {
			return err
		}
	}

	if ip6Addr != "" {
		// Add DNAT rule for IPv6
		_, err = exec.execute("ip6tables", []string{"-t nat -I PREROUTING 1 -p tcp -i", tunID, "-j DNAT --to", fmt.Sprintf("%v:41245", ip6Addr)})
		if err != nil {
			return err
		}

		// Accept traffic to be handled by the kernel on the tun interface in ipv6
		_, err = exec.execute("ip6tables", []string{"-I INPUT 1 -i", tunID, "-j ACCEPT"})
		if err != nil {
			return err
		}
	}

	return nil
}

// createTunSet creates a set of N tun rules by name and index that can be used by this conjure instance
func createTunSet(num int, prefix string, iface string, exec Executor) error {

	dnatAddr, err := getInterfaceAddress(iface, false)
	if err != nil {
		return err
	}

	dnatAddr6, err := getInterfaceAddress(iface, true)
	if err != nil {
		return err
	}

	for i := 0; i < num; i++ {
		err := createTunRule(i, prefix, dnatAddr, dnatAddr6, exec)
		if err != nil {
			return err
		}
	}

	return nil
}

// removeTunRule deletes one tun rule by name and index
func removeTunRule(id int, prefix string, ip4Addr string, ip6Addr string, exec Executor) error {
	var err error
	var tunID = fmt.Sprintf("tun_%s_%d", prefix, id)
	var tableID = fmt.Sprintf("custom_%s", prefix)

	if ip4Addr != "" {
		// remove DNAT rule
		_, err = exec.execute("iptables", []string{"-t nat -D PREROUTING -p tcp -i", tunID, "-j DNAT --to", fmt.Sprintf("%v:41245", ip4Addr)})
		if err != nil {
			return err
		}

		// Remove rule to accept traffic to be handled by the kernel on the tun interface
		_, err = exec.execute("iptables", []string{"-D INPUT -i", tunID, "-j ACCEPT"})
		if err != nil {
			return err
		}
	}

	if ip6Addr != "" {
		// remove DNAT rule for IPv6
		_, err = exec.execute("ip6tables", []string{"-t nat -D PREROUTING -p tcp -i", tunID, "-j DNAT --to", fmt.Sprintf("%v:41245", ip6Addr)})
		if err != nil {
			return err
		}

		// Remove rule to accept traffic to be handled by the kernel on the tun interface in ipv6
		_, err = exec.execute("ip6tables", []string{"-D INPUT -i", tunID, "-j ACCEPT"})
		if err != nil {
			return err
		}
	}

	// Remove reference to local lookup table
	_, err = exec.execute("ip", []string{"rule del iif", tunID, "lookup", tableID})
	if err != nil {
		return err
	}

	// remove reference to local lookup table
	_, err = exec.execute("ip", []string{"route del local 0.0.0.0/0 dev", tunID, "table", tableID})
	if err != nil {
		return err
	}

	// Remove tun interface if it already exists
	_, err = exec.execute("ip", []string{"tuntap del mode tun", tunID})
	if err != nil {
		return err
	}

	return nil
}

// removeTunSet deletes a set of N tun rule by name and index
func removeTunSet(num int, prefix string, exec Executor) error {

	for i := 0; i < num; i++ {
		err := removeTunRule(i, prefix, dnatAddr, dnatAddr6, exec)
		if err != nil {
			return err
		}
	}

	return nil
}

// getInterfaceAddress takes the name of a local interface as an argument and returns the IPv4 or
// IPv6 address associated with that interface
func getInterfaceAddress(interfaceName string, v6 bool) (string, error) {
	var (
		err   error
		ief   *net.Interface
		addrs []net.Addr
		Addr  net.IP
	)
	if ief, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return "", err
	}
	if addrs, err = ief.Addrs(); err != nil { // get addresses
		return "", err
	}
	for _, addr := range addrs {
		if v6 { // get ipv6 address
			if Addr = addr.(*net.IPNet).IP.To4(); Addr == nil {
				Addr = addr.(*net.IPNet).IP.To16()
				return fmt.Sprintf("[%s]", Addr.String()), nil
			}
		} else { // get ipv4 address
			if Addr = addr.(*net.IPNet).IP.To4(); Addr != nil {
				break
			}
		}
	}
	if Addr == nil {
		return "", fmt.Errorf(fmt.Sprintf("interface %s doesn't have an appropriate address\n", interfaceName))
	}
	return Addr.String(), nil
}
