package tests

import (
	"log"
	"net"
	"os"
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

// SetupPhantomConnections registers one session with the provided transport and
// registration manager using a pre-determined kay and phantom subnet file.
func SetupPhantomConnections(manager *dd.RegistrationManager, transport pb.TransportType) (clientToPhantom net.Conn, serverFromPhantom net.Conn, reg *dd.DecoyRegistration) {
	testSubnetPath := os.Getenv("GOPATH") + "/src/github.com/refraction-networking/conjure/application/lib/test/phantom_subnets.toml"
	return SetupPhantomConnectionsSecret(manager, transport, SharedSecret, testSubnetPath)
}

func SetupPhantomConnectionsSecret(manager *dd.RegistrationManager, transport pb.TransportType, sharedSecret []byte, testSubnetPath string) (clientToPhantom net.Conn, serverFromPhantom net.Conn, reg *dd.DecoyRegistration) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

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

	keys, err := dd.GenSharedKeys(sharedSecret, transport)
	if err != nil {
		log.Fatalln("failed to generate shared keys:", err)
	}

	v := uint32(1)
	covert := "1.2.3.4:56789"
	regType := pb.RegistrationSource_API
	gen := uint32(1)
	c2s := &pb.ClientToStation{
		Transport:           &transport,
		CovertAddress:       &covert,
		DecoyListGeneration: &gen,
		ClientLibVersion:    &v,
	}
	reg, err = manager.NewRegistration(c2s, &keys, false, &regType)
	if err != nil {
		log.Fatalln("failed to create new Registration:", err)
	}

	reg.Transport = transport
	if err != nil {
		log.Fatalln("failed to add registration:", err)
	}

	manager.AddRegistration(reg)
	return
}

func SetupRegistrationManager(transports ...Transport) *dd.RegistrationManager {
	manager := dd.NewRegistrationManager(&dd.RegConfig{})
	for _, t := range transports {
		err := manager.AddTransport(t.Index, t.Transport)
		if err != nil {
			log.Fatalln("failed add transport:", err)
		}
	}
	return manager
}
