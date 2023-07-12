package utls

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"regexp"

	"github.com/refraction-networking/conjure/pkg/core"
	dd "github.com/refraction-networking/conjure/pkg/station/lib"
	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	tls "github.com/refraction-networking/utls"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	httpPrefixRegexString = ""
	httpPrefixMinLen      = 32
	hmacString            = "UTLSTransportHMACString"
)

const (
	// Earliest client library version ID that supports destination port randomization
	randomizeDstPortMinVersion uint = 3

	// port range boundaries for prefix transport when randomizing
	portRangeMin = 1024
	portRangeMax = 65535
	minTagLength = 32

	defaultPort = 443

	tlsCHPrefix    = "\x16\x03\x01"
	tlsCHHeaderLen = 5
)

// TODO: using a regex is probably not necessary
var tlsHeaderRegex = regexp.MustCompile(`^\x16\x03\x01(.{2})`)

// Transport provides a struct implementing the Transport, WrappingTransport,
// PortRandomizingTransport, and FixedPortTransport interfaces.
type Transport struct{}

// Name returns the human-friendly name of the transport, implementing the
// Transport interface..
func (Transport) Name() string { return "UTLSTransport" }

// LogPrefix returns the prefix used when including this transport in logs,
// implementing the Transport interface.
func (Transport) LogPrefix() string { return "UTLS" }

// GetIdentifier takes in a registration and returns an identifier for it. This
// identifier should be unique for each registration on a given phantom;
// registrations on different phantoms can have the same identifier.
func (Transport) GetIdentifier(d *dd.DecoyRegistration) string {
	return string(core.ConjureHMAC(d.Keys.SharedSecret, hmacString))
}

// GetProto returns the next layer protocol that the transport uses. Implements
// the Transport interface.
func (Transport) GetProto() pb.IPProto {
	return pb.IPProto_Tcp
}

// ParseParams gives the specific transport an option to parse a generic object
// into parameters provided by the client during registration.
func (Transport) ParseParams(libVersion uint, data *anypb.Any) (any, error) {
	if data == nil {
		return nil, nil
	}

	// For backwards compatibility we create a generic transport params object
	// for transports that existed before the transportParams fields existed.
	if libVersion < randomizeDstPortMinVersion {
		f := false
		return &pb.GenericTransportParams{
			RandomizeDstPort: &f,
		}, nil
	}

	var m = &pb.GenericTransportParams{}
	err := anypb.UnmarshalTo(data, m, proto.UnmarshalOptions{})
	return m, err
}

// ParamStrings returns an array of tag string that will be added to tunStats when a proxy
// session is closed.
func (Transport) ParamStrings(p any) []string {
	return []string{}
}

// GetDstPort Given the library version, a seed, and a generic object
// containing parameters the transport should be able to return the
// destination port that a clients phantom connection will attempt to reach
func (Transport) GetDstPort(libVersion uint, seed []byte, params any) (uint16, error) {

	if libVersion < randomizeDstPortMinVersion {
		return 0, transports.ErrTransportNotSupported
	}

	if params == nil {
		return defaultPort, nil
	}

	parameters, ok := params.(*pb.GenericTransportParams)
	if !ok {
		return 0, fmt.Errorf("bad parameters provided")
	}

	if parameters.GetRandomizeDstPort() {
		return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
	}

	return defaultPort, nil
}

// WrapConnection attempts to wrap the given connection in the transport. It
// takes the information gathered so far on the connection in data, attempts to
// identify itself, and if it positively identifies itself wraps the connection
// in the transport, returning a connection that's ready to be used by others.
//
// If the returned error is nil or non-nil and non-{ transports.ErrTryAgain,
// transports.ErrNotTransport }, the caller may no longer use data or conn.
func (t *Transport) WrapConnection(data *bytes.Buffer, c net.Conn, originalDst net.IP, regManager *dd.RegistrationManager) (*dd.DecoyRegistration, net.Conn, error) {
	dataLen := data.Len()

	if dataLen == 0 {
		return nil, nil, transports.ErrTryAgain
	} else if dataLen < tlsCHHeaderLen {
		// If we don't have enough bytes to check for the clientHello, check if we can rule it out
		// based on the fixed tls header bytes we expect.
		n := int(math.Min(float64(dataLen), float64(len(tlsCHPrefix))))
		if !bytes.Equal(data.Bytes()[:n], []byte(tlsCHPrefix)[:n]) {
			return nil, nil, transports.ErrNotTransport
		}
		return nil, nil, transports.ErrTryAgain
	}

	// 160301{len:2}{clientHello:len}
	out := tlsHeaderRegex.FindSubmatch(data.Bytes())
	if len(out) < 2 {
		return nil, nil, transports.ErrNotTransport
	}

	// First match is the whole pattern, the second should be the group, and based on the regex it
	// should always be the two bytes that we can parse into a u16 for ClientHello length.
	chLen := binary.BigEndian.Uint16(out[1])
	if dataLen < tlsCHHeaderLen+int(chLen) {
		return nil, nil, transports.ErrTryAgain
	}

	ch := tls.UnmarshalClientHello(data.Bytes()[tlsCHHeaderLen:dataLen])
	if ch == nil {
		// We assume that one MTU is enough for the clientHello. If we have read the declared
		// ClientHello length OR more than 1 MTU and still haven't found our registration then we
		// probably wont find it.
		if dataLen >= tlsCHHeaderLen+int(chLen) || dataLen > 1500 {
			return nil, nil, fmt.Errorf("%w: failed to unmarshal tls", transports.ErrNotTransport)
			// fmt.Printf("failed to read request\n%s\n", err)
		}
		return nil, nil, transports.ErrTryAgain
	}

	hmacID := ch.Random
	sessionID := ch.SessionId
	reg, ok := regManager.GetRegistrations(originalDst)[string(xorBytes(sessionID, hmacID))]
	if !ok {
		return nil, nil, transports.ErrNotTransport
	}

	config := &tls.Config{
		Certificates:       make([]tls.Certificate, 2),
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}
	config.Certificates[0].Certificate = [][]byte{testRSACertificate}
	config.Certificates[0].PrivateKey = testRSAPrivateKey
	config.Certificates[1].Certificate = [][]byte{testSNICertificate}
	config.Certificates[1].PrivateKey = testRSAPrivateKey
	config.BuildNameToCertificate()

	tlsConn := tls.Server(transports.PrependToConn(c, data), config)
	return reg, tlsConn, nil
}

func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		return []byte{}
	}

	n := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		n[i] = a[i] ^ b[i]
	}

	return n
}

func fromHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

var testRSAPrivateKey, _ = x509.ParsePKCS1PrivateKey(fromHex("3082025b02010002818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d702030100010281800b07fbcf48b50f1388db34b016298b8217f2092a7c9a04f77db6775a3d1279b62ee9951f7e371e9de33f015aea80660760b3951dc589a9f925ed7de13e8f520e1ccbc7498ce78e7fab6d59582c2386cc07ed688212a576ff37833bd5943483b5554d15a0b9b4010ed9bf09f207e7e9805f649240ed6c1256ed75ab7cd56d9671024100fded810da442775f5923debae4ac758390a032a16598d62f059bb2e781a9c2f41bfa015c209f966513fe3bf5a58717cbdb385100de914f88d649b7d15309fa49024100dd10978c623463a1802c52f012cfa72ff5d901f25a2292446552c2568b1840e49a312e127217c2186615aae4fb6602a4f6ebf3f3d160f3b3ad04c592f65ae41f02400c69062ca781841a09de41ed7a6d9f54adc5d693a2c6847949d9e1358555c9ac6a8d9e71653ac77beb2d3abaf7bb1183aa14278956575dbebf525d0482fd72d90240560fe1900ba36dae3022115fd952f2399fb28e2975a1c3e3d0b679660bdcb356cc189d611cfdd6d87cd5aea45aa30a2082e8b51e94c2f3dd5d5c6036a8a615ed0240143993d80ece56f877cb80048335701eb0e608cc0c1ca8c2227b52edf8f1ac99c562f2541b5ce81f0515af1c5b4770dba53383964b4b725ff46fdec3d08907df"))
var testRSACertificate = fromHex("3082024b308201b4a003020102020900e8f09d3fe25beaa6300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3235303130313030303030305a301a310b3009060355040a1302476f310b300906035504031302476f30819f300d06092a864886f70d010101050003818d0030818902818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d70203010001a38193308190300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff0402300030190603551d0e041204109f91161f43433e49a6de6db680d79f60301b0603551d230414301280104813494d137e1631bba301d5acab6e7b30190603551d1104123010820e6578616d706c652e676f6c616e67300d06092a864886f70d01010b0500038181009d30cc402b5b50a061cbbae55358e1ed8328a9581aa938a495a1ac315a1a84663d43d32dd90bf297dfd320643892243a00bccf9c7db74020015faad3166109a276fd13c3cce10c5ceeb18782f16c04ed73bbb343778d0c1cf10fa1d8408361c94c722b9daedb4606064df4c1b33ec0d1bd42d4dbfe3d1360845c21d33be9fae7")
var testSNICertificate = fromHex("0441883421114c81480804c430820237308201a0a003020102020900e8f09d3fe25beaa6300d06092a864886f70d01010b0500301f310b3009060355040a1302476f3110300e06035504031307476f20526f6f74301e170d3136303130313030303030305a170d3235303130313030303030305a3023310b3009060355040a1302476f311430120603550403130b736e69746573742e636f6d30819f300d06092a864886f70d010101050003818d0030818902818100db467d932e12270648bc062821ab7ec4b6a25dfe1e5245887a3647a5080d92425bc281c0be97799840fb4f6d14fd2b138bc2a52e67d8d4099ed62238b74a0b74732bc234f1d193e596d9747bf3589f6c613cc0b041d4d92b2b2423775b1c3bbd755dce2054cfa163871d1e24c4f31d1a508baab61443ed97a77562f414c852d70203010001a3773075300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b0601050507030106082b06010505070302300c0603551d130101ff0402300030190603551d0e041204109f91161f43433e49a6de6db680d79f60301b0603551d230414301280104813494d137e1631bba301d5acab6e7b300d06092a864886f70d01010b0500038181007beeecff0230dbb2e7a334af65430b7116e09f327c3bbf918107fc9c66cb497493207ae9b4dbb045cb63d605ec1b5dd485bb69124d68fa298dc776699b47632fd6d73cab57042acb26f083c4087459bc5a3bb3ca4d878d7fe31016b7bc9a627438666566e3389bfaeebe6becc9a0093ceed18d0f9ac79d56f3a73f18188988ed")

// TODO:
//
// [X] Fill PSK in client and session cache in station to ensure resumption of legit sessions.
//
// [ ] for TLS 1.3 Use session ticket and XOR rand and sessionID so that neither is (apparently) re-used
// [ ] for TLS 1.2 Use session ticket and XOR rand with session ID.
//
// [ ] utls params for hello id and SNI
//
// [ ] Can we leave certs / private keys out if using psk / session resumption?
// [ ] Alternatively, can we generate the private key dynamically after finding the registration?
//
// If we use one key does that allow clients to connect to other clients coverts? probably.
