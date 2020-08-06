package tests

import (
	"log"
	"net"
	"sync"

	dd "github.com/refraction-networking/conjure/application/lib"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"google.golang.org/grpc/test/bufconn"
)

type Transport struct {
	Index     pb.TransportType
	Transport dd.Transport
}

var SharedSecret = []byte(`6a328b8ec2024dd92dd64332164cc0425ddbde40cb7b81e055bf7b099096d068`)

func SetupPhantomConnections(manager *dd.RegistrationManager, transport pb.TransportType) (clientToPhantom net.Conn, serverFromPhantom net.Conn, reg *dd.DecoyRegistration) {
	phantom := bufconn.Listen(65535)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		c, err := phantom.Accept()
		if err != nil {
			log.Fatalln("failed to accept:", err)
		}
		serverFromPhantom = c
		wg.Done()
	}()

	c, err := phantom.Dial()
	if err != nil {
		log.Fatalln("failed to dial phantom:", err)
	}
	clientToPhantom = c

	wg.Wait()

	keys, err := dd.GenSharedKeys(SharedSecret)
	if err != nil {
		log.Fatalln("failed to generate shared keys:", err)
	}

	covert := "1.2.3.4:56789"
	c2s := &pb.ClientToStation{Transport: &transport, CovertAddress: &covert}
	reg, err = manager.NewRegistration(c2s, &keys, false)
	reg.Transport = transport
	if err != nil {
		log.Fatalln("failed to add registration:", err)
	}

	manager.AddRegistration(reg)
	return
}

func SetupRegistrationManager(transports ...Transport) *dd.RegistrationManager {
	manager := dd.NewRegistrationManager()
	for _, t := range transports {
		manager.AddTransport(t.Index, t.Transport)
	}
	return manager
}
