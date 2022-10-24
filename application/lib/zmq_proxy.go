package lib

//

import (
	"context"
	"fmt"
	golog "log"
	"math"
	"os"
	"sync/atomic"
	"time"

	zmq "github.com/pebbe/zmq4"

	"github.com/refraction-networking/conjure/application/log"
)

// ZMQConfig - Configuration options relevant to the ZMQ Proxy utility
type ZMQConfig struct {
	SocketName        string         `toml:"socket_name"`
	ConnectSockets    []socketConfig `toml:"connect_sockets"`
	PrivateKeyPath    string         `toml:"privkey_path"`
	HeartbeatInterval int            `toml:"heartbeat_interval"`
	HeartbeatTimeout  int            `toml:"heartbeat_timeout"`
}

type socketConfig struct {
	Address            string `toml:"address"`
	AuthenticationType string `toml:"type"`
	PublicKey          string `toml:"pubkey"`
	SubscriptionPrefix string `toml:"subscription"`
}

// ZMQIngester manages registration ingest over ZMQ.
type ZMQIngester struct {
	*ZMQConfig
	logger *log.Logger

	regChan     chan<- interface{}
	connectAddr string

	// stats
	epochStart              time.Time
	droppedZMQMessages      int64 // if the ingest channel ends up blocking how many registrations were dropped this epoch
	totalDroppedZMQMessages int64 // how many registrations have been dropped total due to full channel
	zmqMessages             int64
}

// NewZMQIngest returns a struct that manages registration ingest over ZMQ.
func NewZMQIngest(connectAddr string, regchan chan<- interface{}, conf *ZMQConfig) *ZMQIngester {
	logger := log.New(os.Stdout, "[ZMQ_PROXY] ", golog.Ldate|golog.Lmicroseconds)

	return &ZMQIngester{
		conf,
		logger,
		regchan,
		connectAddr,
		time.Now(),
		0, 0, 0}
}

// RunZMQ start the receive loop that writes into the provided message receive channel
func (zi *ZMQIngester) RunZMQ(ctx context.Context) {
	go zi.proxyZMQ()

	sub, err := zmq.NewSocket(zmq.SUB)
	if err != nil {
		zi.logger.Errorf("could not create new ZMQ socket: %v\n", err)
		return
	}
	defer sub.Close()

	err = sub.Connect(zi.connectAddr)
	if err != nil {
		zi.logger.Errorln("error connecting to zmq publisher:", err)
	}
	err = sub.SetSubscribe("")
	if err != nil {
		zi.logger.Errorln("error subscribing to zmq:", err)
	}

	zi.logger.Infof("ZMQ connected to %v\n", zi.connectAddr)

	for {

		msg, err := sub.RecvBytes(0)
		if err != nil {
			zi.logger.Fatalf("error reading from ZMQ socket: %v\n", err)
		}

		zi.addZMQMessage()

		select {
		case <-ctx.Done():
			return
		case zi.regChan <- msg:
			continue
		default:
			// drop reg, ingest is too busy to handle it.
			zi.logger.Warnln("ingest full, dropping zmq message")
			zi.addDroppedZMQMessage()
		}
	}
}

// Reset implements the Stats interface
func (zi *ZMQIngester) Reset() {
	atomic.StoreInt64(&zi.droppedZMQMessages, 0)
	atomic.StoreInt64(&zi.zmqMessages, 0)
	zi.epochStart = time.Now()
}

func (zi *ZMQIngester) addZMQMessage() {
	atomic.AddInt64(&zi.zmqMessages, 1)
}

func (zi *ZMQIngester) addDroppedZMQMessage() {
	atomic.AddInt64(&zi.droppedZMQMessages, 1)
	atomic.AddInt64(&zi.totalDroppedZMQMessages, 1)
}

// PrintAndReset implements the Stats interface
func (zi *ZMQIngester) PrintAndReset(logger *log.Logger) {
	l := len(zi.regChan)
	c := cap(zi.regChan)
	// prevent div by 0 if thread starvation happens
	var epochDur float64 = math.Max(float64(time.Since(zi.epochStart).Milliseconds()), 1)

	logger.Infof("zmq-stats: %d %d %.3f%% (%.3f/s) %d %d/%d %.3f%%",
		atomic.LoadInt64(&zi.zmqMessages),
		atomic.LoadInt64(&zi.droppedZMQMessages),
		float64(atomic.LoadInt64(&zi.droppedZMQMessages))/math.Max(float64(atomic.LoadInt64(&zi.zmqMessages)), 1)*100,
		1000*float64(atomic.LoadInt64(&zi.droppedZMQMessages))/epochDur, // x1000 convert /ms to /s
		atomic.LoadInt64(&zi.totalDroppedZMQMessages),
		l,
		c,
		float64(l)/float64(c)*100,
	)
	zi.Reset()
}

// ZMQProxy - centralizing proxy used to channel multiple registration sources
// into one PUB socket for consumption by the application. Specify the absolute
// location of the config file with the CJ_PROXY_CONFIG environment variable.
func (zi *ZMQIngester) proxyZMQ() {

	privkey, err := os.ReadFile(zi.PrivateKeyPath)
	if err != nil {
		zi.logger.Fatalln("failed to load private key:", err)
	}

	// Only use first 32 bytes of key (some keys store
	// public key after private key)
	privkeyZ85 := zmq.Z85encode(string(privkey[:32]))
	pubkeyZ85, err := zmq.AuthCurvePublic(privkeyZ85)
	if err != nil {
		zi.logger.Fatalln("failed to generate client public key from private key:", err)
	}

	pubSock, err := zmq.NewSocket(zmq.PUB)
	if err != nil {
		zi.logger.Fatalln("failed to create binding zmq socket:", err)
	}

	err = pubSock.Bind(fmt.Sprintf("ipc://@%s", zi.SocketName))
	if err != nil {
		zi.logger.Fatalln("failed to bind zmq socket:", err)
	}
	defer pubSock.Close()

	messages := make(chan []byte)
	// Create a socket for each socket we're connecting to. I would've
	// liked to use a single socket for all connections, and ZMQ actually
	// does support connecting to multiple sockets from a single socket,
	// but it appears that it doesn't support setting different auth
	// parameters for each connection.
	for _, connectSocket := range zi.ConnectSockets {
		sock, err := zmq.NewSocket(zmq.SUB)
		if err != nil {
			zi.logger.Errorf("failed to create subscriber zmq socket for %s: %v\n", connectSocket.Address, err)
		}

		err = sock.SetHeartbeatIvl(time.Duration(zi.HeartbeatInterval) * time.Millisecond)
		if err != nil {
			zi.logger.Errorf("failed to set heartbeat interval of %v for %s: %v\n", zi.HeartbeatInterval, connectSocket.Address, err)
		}

		err = sock.SetHeartbeatTimeout(time.Duration(zi.HeartbeatTimeout) * time.Millisecond)
		if err != nil {
			zi.logger.Errorf("failed to set heartbeat timeout of %v for %s: %v\n", zi.HeartbeatTimeout, connectSocket.Address, err)
		}

		if connectSocket.AuthenticationType == "CURVE" {
			err = sock.ClientAuthCurve(connectSocket.PublicKey, pubkeyZ85, privkeyZ85)
			if err != nil {
				zi.logger.Errorf("failed to set up CURVE authentication for %s: %v\n", connectSocket.Address, err)
				continue
			}
		}

		err = sock.SetSubscribe(connectSocket.SubscriptionPrefix)
		if err != nil {
			zi.logger.Errorf("failed to set subscription prefix for %s: %v\n", connectSocket.Address, err)
			continue
		}

		err = sock.Connect(connectSocket.Address)
		if err != nil {
			zi.logger.Errorf("failed to connect to %s: %v\n", connectSocket.Address, err)
			continue
		}
		defer sock.Close()

		go func(sub *zmq.Socket, config socketConfig) {
			for {
				msg, err := sub.RecvBytes(0)
				if err != nil {
					zi.logger.Errorf("read from %s failed: %v\n", config.Address, err)
					continue
				}
				messages <- msg
			}
		}(sock, connectSocket)
	}

	for msg := range messages {
		_, err := pubSock.SendBytes(msg, 0)
		if err != nil {
			zi.logger.Errorf("write to pubSock failed: %v\n", err)
		}
	}
}
