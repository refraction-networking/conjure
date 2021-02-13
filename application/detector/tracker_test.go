package main

import (
	"testing"
	"time"

	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/stretchr/testify/require"
)

// TODO: Swap entry for testEntry (more specific)
type entry struct {
	p string
	c string
	t uint64
	e string
	a bool
}

func TestDetectorTrackerBasics(t *testing.T) {
	tr := DefaultTracker{
		sessions: make(map[string]*Entry),
	}

	testsGood := []entry{
		entry{c: "192.168.0.1", p: "10.10.0.1", t: s2ns(time.Second * 1), e: "", a: false},
		entry{c: "2601::123:abcd", p: "2001::1234", t: s2ns(time.Second * 1), e: "", a: false},
		entry{c: "", p: "2001::1234", t: s2ns(time.Second * 1), e: "", a: false},

		// client registering with v4 will also create registrations for v6 just in-case
		entry{c: "192.168.0.1", p: "2801::1234", t: s2ns(time.Second * 1), e: "", a: false},
	}

	for _, e := range testsGood {
		s2d := &pb.StationToDetector{
			ClientIp:  &e.c,
			PhantomIp: &e.p,
			TimeoutNs: &e.t,
		}
		err := tr.Add(s2d)
		require.Nil(t, err)

		key, _ := keyFromParts(e.c, e.p, DefaultPort)
		_, ok := tr.sessions[key]
		require.Equal(t, true, ok)

		require.Equal(t, true, tr.IsRegistered(e.c, e.p, DefaultPort))
	}
}

func TestDetectorTrackerFrom(t *testing.T) {
	// use e as expected key
	testsGood := []entry{
		entry{c: "192.168.0.1", p: "10.10.0.1", t: 100000, e: "192.168.0.1-10.10.0.1", a: false},
		entry{c: "2601::123:abcd", p: "2001::1234", t: 100000, e: "2001::1234", a: false},
		entry{c: "", p: "2001::1234", t: 100000, e: "2001::1234", a: false},

		// client registering with v4 will also create registrations for v6 just in-case
		entry{c: "192.168.0.1", p: "2801::1234", t: 100000, e: "2801::1234", a: false},
	}

	// use e as expected error
	testsBad := []entry{
		// Mixed ipv4/ipv6 phantom/client
		entry{c: "2001::1234", p: "10.10.0.1", t: 100000, e: "Client/Phantom v4/v6 mismatch"},

		// no phantom provided
		entry{c: "192.168.0.1", p: "", t: 100000, e: "Invalid phantom address"},
		entry{c: "2601::123:abcd", p: "", t: 100000, e: "Invalid phantom address"},

		// malformed addresses
		entry{c: "192.1", p: "10.0.0.1", t: 100000, e: "Invalid client address"},
		entry{c: "2001::1234", p: "abcd::123::wrong", t: 100000, e: "Invalid phantom address"},

		// No client provided in ipv4
		entry{c: "", p: "10.10.0.1", t: 100000, e: "Invalid client address"},
	}

	for _, e := range testsGood {
		s2d := &pb.StationToDetector{
			ClientIp:  &e.c,
			PhantomIp: &e.p,
			TimeoutNs: &e.t,
		}

		key, err := keyFromS2D(s2d)
		require.Nil(t, err)
		require.Equal(t, e.e, key)
	}

	for _, e := range testsBad {
		s2d := &pb.StationToDetector{
			ClientIp:  &e.c,
			PhantomIp: &e.p,
			TimeoutNs: &e.t,
		}

		// Expects error
		_, err := keyFromS2D(s2d)
		require.Equal(t, e.e, err.Error())
	}
}

func TestDetectorTrackerTimeouts(t *testing.T) {
	tr := NewTracker()

	testsGood := []entry{
		// (client_ip, phantom_ip, timeout)
		entry{c: "172.128.0.2", p: "8.0.0.1", t: 1, a: false}, // timeout immediately
		entry{c: "192.168.0.1", p: "10.10.0.1", t: s2ns(time.Second * 5), a: true},
		entry{c: "192.168.0.1", p: "192.0.0.127", t: s2ns(time.Second * 5), a: true},

		// client registering with v4 will also create registrations for v6 just in-case
		entry{c: "192.168.0.1", p: "2801::1234", t: s2ns(time.Second * 5), a: true},

		// duplicate with shorter timeout should not drop
		entry{c: "2601::123:abcd", p: "2001::1234", t: s2ns(time.Second * 5), a: true},
		entry{c: "::1", p: "2001::1234", t: s2ns(time.Second * 1), a: true},

		// duplicate with long timeout should prevent drop
		entry{c: "7.0.0.2", p: "8.8.8.8", t: 1, a: true},
		entry{c: "7.0.0.2", p: "8.8.8.8", t: s2ns(time.Second * 5), a: true},
	}

	for _, e := range testsGood {
		s2d := &pb.StationToDetector{
			ClientIp:  &e.c,
			PhantomIp: &e.p,
			TimeoutNs: &e.t,
		}

		err := tr.Add(s2d)
		require.Nil(t, err)
	}

	time.Sleep(time.Second * 3)

	exp, err := tr.RemoveExpired()
	require.Nil(t, err)
	require.Equal(t, 1, exp)

	for _, e := range testsGood {
		r := tr.IsRegistered(e.c, e.p, DefaultPort)
		if e.a != r {
			t.Fatalf("got: %v, expected: %v - %v->%v", r, e.a, e.c, e.p)
		}
		// require.Equal(t, e.a, tr.IsRegistered(e.c, e.p, DefaultPort))
	}

	time.Sleep(time.Second * 3)

	exp, err = tr.RemoveExpired()
	require.Nil(t, err)
	require.Equal(t, 5, exp)
}
