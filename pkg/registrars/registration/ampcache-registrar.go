package registration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/refraction-networking/conjure/pkg/registrars/lib"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/gotapdance/tapdance"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/amp"
)

const (
	readLimit = 100000 //Maximum number of bytes to be read from an HTTP response
)

type AMPCacheRegistrar struct {
	// endpoint to use in registration request
	endpoint    string
	ampCacheURL string
	// HTTP client to use in request
	client           *http.Client
	utlsDistribution string
	maxRetries       int
	connectionDelay  time.Duration
	bidirectional    bool
	ip               []byte
	Pubkey           []byte
	logger           logrus.FieldLogger
}

func NewAMPCacheRegistrar(config *Config) (*AMPCacheRegistrar, error) {

	var err error
	if config.AMPCacheURL == "" {
		return nil, fmt.Errorf("AMPCacheURL not set")
	}

	ip, err := getPublicIp(config.STUNAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get public IP: %v", err)
	}

	return &AMPCacheRegistrar{
		endpoint:         config.Target,
		client:           config.HTTPClient,
		ampCacheURL:      config.AMPCacheURL,
		ip:               ip,
		utlsDistribution: config.UTLSDistribution,
		maxRetries:       config.MaxRetries,
		bidirectional:    config.Bidirectional,
		connectionDelay:  config.Delay,
		logger:           tapdance.Logger().WithField("registrar", "AMPCache"),
	}, nil
}

// registerBidirectional sends bidirectional registration data to the registration server and reads the response
func (r *AMPCacheRegistrar) registerBidirectional(ctx context.Context, cjSession *tapdance.ConjureSession) (*tapdance.ConjureReg, error) {
	logger := r.logger.WithFields(logrus.Fields{"type": "ampcache-bidirectional", "sessionID": cjSession.IDString()})

	reg, protoPayload, err := cjSession.BidirectionalRegData(ctx, pb.RegistrationSource_BidirectionalAMP.Enum())
	if err != nil {
		logger.Errorf("Failed to prepare registration data: %v", err)
		return nil, lib.ErrRegFailed
	}
	logger.Printf("IP address %s", string(r.ip))

	protoPayload.RegistrationAddress = r.ip

	payload, err := proto.Marshal(protoPayload)
	if err != nil {
		logger.Errorf("failed to marshal ClientToStation payload: %v", err)
		return nil, lib.ErrRegFailed
	}

	r.setAMPCacheHTTPClient(reg)

	logger.Debugf("AMPCache payload length: %d", len(payload))

	for i := 0; i < r.maxRetries+1; i++ {
		logger := logger.WithField("attempt", strconv.Itoa(i+1)+"/"+strconv.Itoa(r.maxRetries))

		regResp, err := r.executeAMPCacheRequestBidirectional(ctx, payload, logger)

		if err != nil {
			logger.Warnf("error sending request to AMPCache registrar: %v", err)
			continue
		}

		err = reg.UnpackRegResp(regResp)
		if err != nil {
			logger.Warnf("failed to unpack registration response: %v", err)
			continue
		}
		return reg, nil
	}

	logger.WithField("maxTries", r.maxRetries).Warnf("all registration attemps failed")

	return nil, lib.ErrRegFailed
}

func (r *AMPCacheRegistrar) setAMPCacheHTTPClient(reg *tapdance.ConjureReg) {
	if r.client == nil {
		// Transports should ideally be re-used for TCP connection pooling,
		// but each registration is most likely making precisely one request,
		// or if it's making more than one, is most likely due to an underlying
		// connection issue rather than an application-level error anyways.
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.DialContext = reg.Dialer
		r.client = &http.Client{Transport: t}
	}

}

func (r AMPCacheRegistrar) executeAMPCacheRequestBidirectional(ctx context.Context, payload []byte, logger logrus.FieldLogger) (*pb.RegistrationResponse, error) {
	// Create an instance of the ConjureReg struct to return; this will hold the updated phantom4 and phantom6 addresses received from registrar response
	regResp := &pb.RegistrationResponse{}
	// Make new HTTP request with given context, registrar, and paylaod
	logger.Println("Registering via AMP cache rendezvous...")
	logger.Println("Station URL:", r.endpoint)
	logger.Println("AMP cache URL:", r.ampCacheURL)

	endpointURL, err := url.Parse(r.endpoint)
	if err != nil {
		logger.Warnf("failed to parse endpoint url")
	}
	reqURL := endpointURL.ResolveReference(&url.URL{
		Path: endpointURL.Path + "/" + amp.EncodePath(payload),
	})

	// Rewrite reqURL to its AMP cache version.
	ampURL, err := url.Parse(r.ampCacheURL)
	if err != nil {
		logger.Warnf("failed to parse ampcache url")
	}
	reqURL, err = amp.CacheURL(reqURL, ampURL, "c")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)
	if err != nil {
		logger.Warnf("%v failed to create HTTP request to registration endpoint %s: %v", r.endpoint, err)
		return regResp, err
	}
	logger.Printf("Request: %v", req)
	resp, err := r.client.Do(req)
	if err != nil {
		logger.Warnf("%v failed to do HTTP request to registration endpoint %s: %v", r.endpoint, err)
		return regResp, err
	}
	logger.Printf("Response: %v", resp)
	defer resp.Body.Close()

	logger.Printf("AMP cache rendezvous response: %s", resp.Status)

	// Check that the HTTP request returned a success code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// logger.Warnf("got non-success response code %d from registration endpoint %v", resp.StatusCode, r.endpoint)
		return regResp, fmt.Errorf("non-success response code %d on %s", resp.StatusCode, r.endpoint)
	}

	if _, err := resp.Location(); err == nil {
		// The Google AMP Cache may return a "silent redirect" with
		// status 200, a Location header set, and a JavaScript redirect
		// in the body. The redirect points directly at the origin
		// server for the request (bypassing the AMP cache). We do not
		// follow redirects nor execute JavaScript, but in any case we
		// cannot extract information from this response and can only
		// treat it as an error.
		return nil, fmt.Errorf("non-success silent redirect %d on %s", resp.StatusCode, r.endpoint)
	}

	lr := io.LimitReader(resp.Body, readLimit+1)
	dec, err := amp.NewArmorDecoder(lr)
	if err != nil {
		return nil, fmt.Errorf("Armor Decoder failed with error: %d", err)
	}
	bodyBytes, err := io.ReadAll(dec)
	if err != nil {
		return nil, fmt.Errorf("ReadAll failed with error: %d", err)
	}
	if lr.(*io.LimitedReader).N == 0 {
		// We hit readLimit while decoding AMP armor, that's an error.
		return nil, fmt.Errorf("Hit readLimit while decoding AMP armor: %d", io.ErrUnexpectedEOF)
	}
	// Unmarshal response body into Registration Response protobuf
	if err = proto.Unmarshal(bodyBytes, regResp); err != nil {

		return regResp, fmt.Errorf("Error in storing Registration Response protobuf: %v", err)
	}
	return regResp, nil
}

// Register prepares and sends the registration request.
func (r *AMPCacheRegistrar) Register(cjSession *tapdance.ConjureSession, ctx context.Context) (*tapdance.ConjureReg, error) {
	defer lib.SleepWithContext(ctx, r.connectionDelay)

	//	if r.bidirectional {
	return r.registerBidirectional(ctx, cjSession)
	//	}
	//	return r.registerUnidirectional(ctx, cjSession)
}

// PrepareRegKeys prepares key materials specific to the registrar
func (r *AMPCacheRegistrar) PrepareRegKeys(stationPubkey [32]byte, sessionSecret []byte) error {

	return nil
}
