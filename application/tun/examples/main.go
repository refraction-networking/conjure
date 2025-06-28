package main

// This functions as a unit test for the tun module which requires root to run
// (creating and deleting interfaces)

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/refraction-networking/conjure/application/tun"
)

func main() {
	testTunToTun()

	testListenOverTun()

	testWriteOverTun()
}

func testTunToTun() {

	tun2, err := tun.NewTun("tun2")
	if err != nil {
		fmt.Println("Failed to open tun - ", err)
		return
	}
	defer tun2.Close()

	tun3, err := tun.NewTun("tun3")
	if err != nil {
		fmt.Println("Failed to open tun - ", err)
		return
	}
	defer tun3.Close()

	for i, tun := range []*tun.Tun{tun2, tun3} {
		err = tun.SetOwner(1001)
		if err != nil {
			fmt.Println("Failed to set owner - ", err)
			return
		}

		err = tun.SetGroup(1001)
		if err != nil {
			fmt.Println("Failed to set group - ", err)
			return
		}

		if i == 0 {
			err = tun.SetIPv4("10.0.0.1")
			if err != nil {
				fmt.Println("Failed to set ipv4 - ", err)
				return
			}

			err = tun.SetIPv6("fe80::0db8:1234:1211")
			if err != nil {
				fmt.Println("Failed to set ipv6 - ", err)
				return
			}

		} else {
			err = tun.SetIPv4("10.0.0.2")
			if err != nil {
				fmt.Println("Failed to set ipv4 - ", err)
				return
			}

			err = tun.SetIPv6("fe80::0db8:1234:1212")
			if err != nil {
				fmt.Println("Failed to set ipv6 - ", err)
				return
			}
		}
		err = tun.SetMTU(1400)
		if err != nil {
			fmt.Println("Failed to set MTU - ", err)
			return
		}

		err = tun.SetUp()
		if err != nil {
			fmt.Println("Failed to set tun device 'UP' - ", err)
			return
		}
	}

	go func() {
		buf0 := make([]byte, 1400)
		for {
			_, err = tun3.Read(buf0)
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Println("Error reading from Tun", err)
				continue
			}

			_, err = tun2.Write(buf0)
		}
	}()
	// read 1024 bytes at a time
	buf1 := make([]byte, 1400)
	for {
		_, err = tun2.Read(buf1)
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Println("Error reading from Tun", err)
			continue
		}

		_, err = tun3.Write(buf1)
	}
}

func testWriteOverTun() {
	tun1, err := tun.NewTun("tun1")
	if err != nil {
		fmt.Println("Failed to open tun - ", err)
		return
	}
	if tun1 == nil {
		return
	}

	defer tun1.Close()
	var wg sync.WaitGroup

	go func() {

		wg.Add(1)
		defer wg.Done()

		// read 1024 bytes at a time
		buf := make([]byte, 1024)

		for {

			n, err := tun1.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Println("Error reading from Tun", err)
				continue
			}

			fmt.Println(n, string(buf[:n]))
		}
	}()

	time.Sleep(1 * time.Second)

	if handle, err := pcap.OpenOffline("min.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {

			// Missing Packet information 4 byte header
			//	see https://github.com/songgao/water/issues/18
			var writePrepare [2000]byte
			// copy(writePrepare[:], []byte{0, 0, 0, 2})
			n := copy(writePrepare[4:], packet.Data())

			n, err := tun1.Write(writePrepare[:4+n])
			if err != nil {
				fmt.Println("Error writing into tun - ", err)
				break
			}
			fmt.Println("wrote", n, "bytes")
		}
	}

	// tun1.Write([]byte("hello"))
	wg.Wait()
}

func testListenOverTun() {

}
