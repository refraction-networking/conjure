package iface

import (
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"testing"
)

type funcExecutor struct {
	handle func(program string, args []string) ([]byte, error)
}

func (fe *funcExecutor) execute(program string, args []string) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("Can't Execute this on a windows machine")
	}

	return fe.handle(program, args)
}

func TestIfaceExecutorWithArgs(t *testing.T) {

	ex := &executor{}

	expected := "testing the output"

	out, err := ex.execute("echo", []string{"-n", expected})
	if err != nil {
		t.Fatalf("execute threw error: %v", err)
	}

	if string(out) != expected {
		t.Fatalf("expected '%s', got '%s'", expected, string(out))
	}
}

func TestIfaceExecutorSed(t *testing.T) {

	ex := &executor{}
	expected := "testing the output"
	fname, err := ioutil.TempFile("", "conjure-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	t.Log(fname.Name())
	defer os.Remove(fname.Name()) // clean up

	fname, err = os.Open(fname.Name())
	if err != nil {
		t.Fatal(err)
	}

	// sed -i '$ a This is the last line'
	res, err := ex.execute("sed", []string{"-i", "'$ a testing the output'", fname.Name()})
	if err != nil {
		t.Fatalf("execute threw error: %v - %s", err, string(res))
	}

	var out []byte
	_, err = fname.Read(out)
	if err != nil {
		t.Fatal(err)
	}

	if string(out) != expected {
		t.Fatalf("expected '%s', got '%s'", expected, string(out))
	}
}

func TestIfaceCreateTunRule(t *testing.T) {
	execCallCount := 0
	expectedExecStrings := []string{
		"ip tuntap del mode tun tun_cj1_2",
		"ip tuntap add mode tun tun_cj1_2",
		"ip rule add iif tun_cj1_2 lookup custom_cj1",
		"ip route add local 0.0.0.0/0 dev tun_cj1_2 table custom_cj1",
		"sysctl -w net.ipv4.conf.tun_cj1_2.rp_filter=0",
		"iptables -t nat -I PREROUTING 1 -p tcp -i tun_cj1_2 -j DNAT --to 192.168.1.112:41245",
		"iptables -I INPUT 1 -i tun_cj1_2 -j ACCEPT",
		"ip6tables -t nat -I PREROUTING 1 -p tcp -i tun_cj1_2 -j DNAT --to [2601:282:830:a80:0000:444b:307:3f]:41245",
		"ip6tables -I INPUT 1 -i tun_cj1_2 -j ACCEPT",
	}
	fe := &funcExecutor{
		handle: func(program string, args []string) ([]byte, error) {
			cmd := strings.Join(append([]string{program}, args...), " ")

			if execCallCount >= len(expectedExecStrings) {
				return nil, fmt.Errorf("Unexpected extra call to execute")
			}

			expected := expectedExecStrings[execCallCount]
			if cmd != expected {
				return nil, fmt.Errorf("expected/got\n'%s',\n'%s'", expected, cmd)
			}
			execCallCount++
			return nil, nil
		},
	}

	err := createTunRule(2, "cj1", "192.168.1.112", "[2601:282:830:a80:0000:444b:307:3f]", fe)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if execCallCount < len(expectedExecStrings) {
		t.Fatalf("Missed %d calls to execute", len(expectedExecStrings)-execCallCount)
	}
}

func TestIfaceCreateTunRuleNoIPv6(t *testing.T) {
	execCallCount := 0
	expectedExecStrings := []string{
		"ip tuntap del mode tun tun_cj1_2",
		"ip tuntap add mode tun tun_cj1_2",
		"ip rule add iif tun_cj1_2 lookup custom_cj1",
		"ip route add local 0.0.0.0/0 dev tun_cj1_2 table custom_cj1",
		"sysctl -w net.ipv4.conf.tun_cj1_2.rp_filter=0",
		"iptables -t nat -I PREROUTING 1 -p tcp -i tun_cj1_2 -j DNAT --to 192.168.1.112:41245",
		"iptables -I INPUT 1 -i tun_cj1_2 -j ACCEPT",
	}
	fe := &funcExecutor{
		handle: func(program string, args []string) ([]byte, error) {
			cmd := strings.Join(append([]string{program}, args...), " ")

			if execCallCount >= len(expectedExecStrings) {
				return nil, fmt.Errorf("Unexpected extra call to execute")
			}

			expected := expectedExecStrings[execCallCount]
			if cmd != expected {
				return nil, fmt.Errorf("expected/got\n'%s',\n'%s'", expected, cmd)
			}
			execCallCount++
			return nil, nil
		},
	}

	err := createTunRule(2, "cj1", "192.168.1.112", "", fe)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if execCallCount < len(expectedExecStrings) {
		t.Fatalf("Missed %d calls to execute", len(expectedExecStrings)-execCallCount)
	}
}

func TestIfaceCreateTunRuleNoIPv4(t *testing.T) {
	execCallCount := 0
	expectedExecStrings := []string{
		"ip tuntap del mode tun tun_cj1_2",
		"ip tuntap add mode tun tun_cj1_2",
		"ip rule add iif tun_cj1_2 lookup custom_cj1",
		"ip route add local 0.0.0.0/0 dev tun_cj1_2 table custom_cj1",
		"sysctl -w net.ipv4.conf.tun_cj1_2.rp_filter=0",
		"ip6tables -t nat -I PREROUTING 1 -p tcp -i tun_cj1_2 -j DNAT --to [2601:282:830:a80:0000:444b:307:3f]:41245",
		"ip6tables -I INPUT 1 -i tun_cj1_2 -j ACCEPT",
	}
	fe := &funcExecutor{
		handle: func(program string, args []string) ([]byte, error) {
			cmd := strings.Join(append([]string{program}, args...), " ")

			if execCallCount >= len(expectedExecStrings) {
				return nil, fmt.Errorf("Unexpected extra call to execute")
			}

			expected := expectedExecStrings[execCallCount]
			if cmd != expected {
				return nil, fmt.Errorf("expected/got\n'%s',\n'%s'", expected, cmd)
			}
			execCallCount++
			return nil, nil
		},
	}

	err := createTunRule(2, "cj1", "", "[2601:282:830:a80:0000:444b:307:3f]", fe)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if execCallCount < len(expectedExecStrings) {
		t.Fatalf("Missed %d calls to execute", len(expectedExecStrings)-execCallCount)
	}
}

func TestIfaceCreateTunRuleNoAddrs(t *testing.T) {
	fe := &funcExecutor{
		handle: func(program string, args []string) ([]byte, error) {
			return nil, fmt.Errorf("This shouldn't be called in this situation")
		},
	}
	err := createTunRule(2, "cj1", "", "", fe)
	if err.Error() != "Must supply at least one address for tun interfaces" {
		t.FailNow()
	}
}

func TestIfaceRemoveTunRule(t *testing.T) {

	execCallCount := 0
	expectedExecStrings := []string{
		"iptables -t nat -D PREROUTING -p tcp -i tun_cj1_2 -j DNAT --to 192.168.1.112:41245",
		"iptables -D INPUT -i tun_cj1_2 -j ACCEPT",
		"ip6tables -t nat -D PREROUTING -p tcp -i tun_cj1_2 -j DNAT --to [2601:282:830:a80:0000:444b:307:3f]:41245",
		"ip6tables -D INPUT -i tun_cj1_2 -j ACCEPT",
		"ip rule del iif tun_cj1_2 lookup custom_cj1",
		"ip route del local 0.0.0.0/0 dev tun_cj1_2 table custom_cj1",
		"ip tuntap del mode tun tun_cj1_2",
	}
	fe := &funcExecutor{
		handle: func(program string, args []string) ([]byte, error) {
			cmd := strings.Join(append([]string{program}, args...), " ")

			if execCallCount >= len(expectedExecStrings) {
				return nil, fmt.Errorf("Unexpected extra call to execute")
			}

			expected := expectedExecStrings[execCallCount]
			if cmd != expected {
				return nil, fmt.Errorf("expected/got\n'%s',\n'%s'", expected, cmd)
			}
			execCallCount++
			return nil, nil
		},
	}

	err := removeTunRule(2, "cj1", "192.168.1.112", "[2601:282:830:a80:0000:444b:307:3f]", fe)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if execCallCount < len(expectedExecStrings) {
		t.Fatalf("Missed %d calls to execute", len(expectedExecStrings)-execCallCount)
	}
}

func TestIfaceRemoveTunSet(t *testing.T) {

	dnatAddr = "192.168.1.112"
	dnatAddr6 = "[2601:282:830:a80:0000:444b:307:3f]"
	execCallCount := 0
	expectedExecStrings := []string{
		"iptables -t nat -D PREROUTING -p tcp -i tun_cj1_0 -j DNAT --to 192.168.1.112:41245",
		"iptables -D INPUT -i tun_cj1_0 -j ACCEPT",
		"ip6tables -t nat -D PREROUTING -p tcp -i tun_cj1_0 -j DNAT --to [2601:282:830:a80:0000:444b:307:3f]:41245",
		"ip6tables -D INPUT -i tun_cj1_0 -j ACCEPT",
		"ip rule del iif tun_cj1_0 lookup custom_cj1",
		"ip route del local 0.0.0.0/0 dev tun_cj1_0 table custom_cj1",
		"ip tuntap del mode tun tun_cj1_0",

		"iptables -t nat -D PREROUTING -p tcp -i tun_cj1_1 -j DNAT --to 192.168.1.112:41245",
		"iptables -D INPUT -i tun_cj1_1 -j ACCEPT",
		"ip6tables -t nat -D PREROUTING -p tcp -i tun_cj1_1 -j DNAT --to [2601:282:830:a80:0000:444b:307:3f]:41245",
		"ip6tables -D INPUT -i tun_cj1_1 -j ACCEPT",
		"ip rule del iif tun_cj1_1 lookup custom_cj1",
		"ip route del local 0.0.0.0/0 dev tun_cj1_1 table custom_cj1",
		"ip tuntap del mode tun tun_cj1_1",
	}

	fe := &funcExecutor{
		handle: func(program string, args []string) ([]byte, error) {
			cmd := strings.Join(append([]string{program}, args...), " ")

			if execCallCount >= len(expectedExecStrings) {
				return nil, fmt.Errorf("Unexpected extra call to execute")
			}

			expected := expectedExecStrings[execCallCount]
			if cmd != expected {
				return nil, fmt.Errorf("expected/got\n'%s',\n'%s'", expected, cmd)
			}
			execCallCount++
			return nil, nil
		},
	}

	err := removeTunSet(2, "cj1", fe)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if execCallCount < len(expectedExecStrings) {
		t.Fatalf("Missed %d calls to execute", len(expectedExecStrings)-execCallCount)
	}
}

func TestIfaceCreateTunSet(t *testing.T) {
	execCallCount := 0
	expectedExecStrings := []string{
		"ip tuntap del mode tun tun_cj1_0",
		"ip tuntap add mode tun tun_cj1_0",
		"ip rule add iif tun_cj1_0 lookup custom_cj1",
		"ip route add local 0.0.0.0/0 dev tun_cj1_0 table custom_cj1",
		"sysctl -w net.ipv4.conf.tun_cj1_0.rp_filter=0",
		"iptables -t nat -I PREROUTING 1 -p tcp -i tun_cj1_0 -j DNAT --to 127.0.0.1:41245",
		"iptables -I INPUT 1 -i tun_cj1_0 -j ACCEPT",
		"ip6tables -t nat -I PREROUTING 1 -p tcp -i tun_cj1_0 -j DNAT --to [::1]:41245",
		"ip6tables -I INPUT 1 -i tun_cj1_0 -j ACCEPT",

		"ip tuntap del mode tun tun_cj1_1",
		"ip tuntap add mode tun tun_cj1_1",
		"ip rule add iif tun_cj1_1 lookup custom_cj1",
		"ip route add local 0.0.0.0/0 dev tun_cj1_1 table custom_cj1",
		"sysctl -w net.ipv4.conf.tun_cj1_1.rp_filter=0",
		"iptables -t nat -I PREROUTING 1 -p tcp -i tun_cj1_1 -j DNAT --to 127.0.0.1:41245",
		"iptables -I INPUT 1 -i tun_cj1_1 -j ACCEPT",
		"ip6tables -t nat -I PREROUTING 1 -p tcp -i tun_cj1_1 -j DNAT --to [::1]:41245",
		"ip6tables -I INPUT 1 -i tun_cj1_1 -j ACCEPT",
	}
	fe := &funcExecutor{
		handle: func(program string, args []string) ([]byte, error) {
			cmd := strings.Join(append([]string{program}, args...), " ")

			if execCallCount >= len(expectedExecStrings) {
				return nil, fmt.Errorf("Unexpected extra call to execute")
			}

			expected := expectedExecStrings[execCallCount]
			if cmd != expected {
				return nil, fmt.Errorf("expected/got\n'%s',\n'%s'", expected, cmd)
			}
			execCallCount++
			return nil, nil
		},
	}

	err := createTunSet(2, "cj1", "lo", fe)
	if err != nil {
		t.Fatalf("failed: %v", err)
	}
	if execCallCount < len(expectedExecStrings) {
		t.Fatalf("Missed %d calls to execute", len(expectedExecStrings)-execCallCount)
	}
}

func TestGetInterfaceAddress(t *testing.T) {
	iface := "lo"
	addr, err := getInterfaceAddress(iface, false)
	if err != nil {
		t.Fatalf("Failed to get ipv4 address: %v", err)
	}

	expected := "127.0.0.1"
	if addr != expected {
		t.Fatalf("expected %s, got %s", expected, addr)
	}

	addr6, err := getInterfaceAddress(iface, true)
	if err != nil {
		t.Fatalf("Failed to get ipv6 address: %v", err)
	}

	expected = "[::1]"
	if addr6 != expected {
		t.Fatalf("expected %s, got %s", expected, addr6)
	}
}
