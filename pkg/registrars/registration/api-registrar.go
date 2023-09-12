package registration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	golog "log"
	"net/http"
	"os"
	"time"

	"github.com/refraction-networking/conjure/pkg/client"
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/log"
	"github.com/refraction-networking/conjure/pkg/registrars/lib"
	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
)

// APIRegistrar implements a registration strategy using a centralized REST API to create
// registrations. Only the Endpoint need be specified; the remaining fields are valid with their
// zero values and provide the opportunity for additional control over the process.
type APIRegistrar struct {
	// endpoint to use in registration request
	endpoint string

	// HTTP client to use in request
	client *http.Client

	// Wether registrations should be bidirectional
	bidirectional bool

	// Length of time to delay after confirming successful
	// registration before attempting a connection,
	// allowing for propagation throughout the stations.
	connectionDelay time.Duration

	// Maximum number of retries before giving up
	maxRetries int

	// A secondary registration method to use on failure.
	// Because the API registration can give us definite
	// indication of a failure to register, this can be
	// used as a "backup" in the case of the API being
	// down or being blocked.
	//
	// If this field is nil, no secondary registration will
	// be attempted. If it is non-nil, after failing to register
	// (retrying MaxRetries times) we will fall back to
	// the Register method on this field.
	secondaryRegistrar interfaces.Registrar

	// Logger to use.
	logger *log.Logger
}

func NewAPIRegistrar(config *Config) (*APIRegistrar, error) {
	return &APIRegistrar{
		endpoint:           config.Target,
		bidirectional:      config.Bidirectional,
		connectionDelay:    config.Delay,
		maxRetries:         config.MaxRetries,
		secondaryRegistrar: config.SecondaryRegistrar,
		client:             config.HTTPClient,
		logger:             log.New(os.Stdout, "reg: API, ", golog.Ldate|golog.Lmicroseconds),
	}, nil
}

// PrepareRegKeys prepares key materials specific to the registrar
func (r *APIRegistrar) PrepareRegKeys(pubkey [32]byte) error {
	return nil
}

// registerUnidirectional sends unidirectional registration data to the registration server
func (r *APIRegistrar) registerUnidirectional(ctx context.Context, cjSession *client.ConjureSession) (*client.ConjureReg, error) {
	logger := log.New(os.Stdout, fmt.Sprintf("type: unidirectional, sessionID: %s", cjSession.IDString()), golog.Ldate|golog.Lmicroseconds)

	reg, protoPayload, err := cjSession.UnidirectionalRegData(ctx, pb.RegistrationSource_API.Enum())
	if err != nil {
		logger.Errorf("Failed to prepare registration data: %v", err)
		return nil, lib.ErrRegFailed
	}

	payload, err := proto.Marshal(protoPayload)
	if err != nil {
		logger.Errorf("failed to marshal ClientToStation payload: %v", err)
		return nil, lib.ErrRegFailed
	}

	r.setHTTPClient(reg)

	for tries := 0; tries < r.maxRetries+1; tries++ {
		err = r.executeHTTPRequest(ctx, payload, logger)
		if err != nil {
			logger.Warnf("error in registration attempt %d/%d: %v", tries+1, r.maxRetries+1, err)
			continue
		}
		logger.Debugf("registration succeeded")
		return reg, nil
	}

	// If we make it here, we failed API registration
	logger.Warnf("attempts: %d, all registration attempt(s) failed", r.maxRetries+1)

	if r.secondaryRegistrar != nil {
		logger.Debugf("trying secondary registration method")
		r, err := r.secondaryRegistrar.Register(ctx, cjSession)
		return r.(*client.ConjureReg), err
	}

	return nil, lib.ErrRegFailed
}

// registerBidirectional sends bidirectional registration data to the registration server and reads the response
func (r *APIRegistrar) registerBidirectional(ctx context.Context, cjSession *client.ConjureSession) (*client.ConjureReg, error) {
	logger := log.New(os.Stdout, fmt.Sprintf("type: bidirectional, sessionID: %s", cjSession.IDString()), golog.Ldate|golog.Lmicroseconds)

	reg, protoPayload, err := cjSession.BidirectionalRegData(ctx, pb.RegistrationSource_BidirectionalAPI.Enum())
	if err != nil {
		logger.Errorf("Failed to prepare registration data: %v", err)
		return nil, lib.ErrRegFailed
	}

	payload, err := proto.Marshal(protoPayload)
	if err != nil {
		logger.Errorf("failed to marshal ClientToStation payload: %v", err)
		return nil, lib.ErrRegFailed
	}

	r.setHTTPClient(reg)

	for tries := 0; tries < r.maxRetries+1; tries++ {
		regResp, err := r.executeHTTPRequestBidirectional(ctx, payload, logger)
		if err != nil {
			logger.Warnf("error in registration attempt %d/%d: %v", tries+1, r.maxRetries+1, err)
			continue
		}

		err = reg.UnpackRegResp(regResp)
		if err != nil {
			return nil, err
		}

		return reg, nil
	}

	// If we make it here, we failed API registration
	if r.secondaryRegistrar != nil {
		logger.Debugf("attempts: %d, trying secondary registration method", r.maxRetries+1)
		r, err := r.secondaryRegistrar.Register(ctx, cjSession)
		return r.(*client.ConjureReg), err
	}

	return nil, lib.ErrRegFailed
}

func (r *APIRegistrar) setHTTPClient(reg *client.ConjureReg) {
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

func (r APIRegistrar) Register(ctx context.Context, cjSession *client.ConjureSession) (*client.ConjureReg, error) {
	defer lib.SleepWithContext(ctx, r.connectionDelay)
	if r.bidirectional {
		return r.registerBidirectional(ctx, cjSession)
	}

	return r.registerUnidirectional(ctx, cjSession)

}

func (r APIRegistrar) executeHTTPRequest(ctx context.Context, payload []byte, logger *log.Logger) error {
	req, err := http.NewRequestWithContext(ctx, "POST", r.endpoint, bytes.NewReader(payload))
	if err != nil {
		logger.Warnf("failed to create HTTP request to registration endpoint %s: %v", r.endpoint, err)
		return err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		logger.Warnf("failed to do HTTP request to registration endpoint %s: %v", r.endpoint, err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// logger.Warnf("got non-success response code %d from registration endpoint %v", resp.StatusCode, r.endpoint)
		return fmt.Errorf("non-success response code %d on %s", resp.StatusCode, r.endpoint)
	}

	return nil
}

func (r APIRegistrar) executeHTTPRequestBidirectional(ctx context.Context, payload []byte, logger *log.Logger) (*pb.RegistrationResponse, error) {
	// Create an instance of the ConjureReg struct to return; this will hold the updated phantom4 and phantom6 addresses received from registrar response
	regResp := &pb.RegistrationResponse{}
	// Make new HTTP request with given context, registrar, and paylaod
	req, err := http.NewRequestWithContext(ctx, "POST", r.endpoint, bytes.NewReader(payload))
	if err != nil {
		logger.Warnf("failed to create HTTP request to registration endpoint %s: %v", r.endpoint, err)
		return regResp, err
	}

	resp, err := r.client.Do(req)
	if err != nil {
		logger.Warnf("failed to do HTTP request to registration endpoint %s: %v", r.endpoint, err)
		return regResp, err
	}
	defer resp.Body.Close()

	// Check that the HTTP request returned a success code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// logger.Warnf("got non-success response code %d from registration endpoint %v", resp.StatusCode, r.endpoint)
		return regResp, fmt.Errorf("non-success response code %d on %s", resp.StatusCode, r.endpoint)
	}

	// Read the HTTP response body into []bytes
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Warnf("error in serializing Registration Response protobuf in bytes: %v", err)
		return regResp, err
	}

	// Unmarshal response body into Registration Response protobuf
	if err = proto.Unmarshal(bodyBytes, regResp); err != nil {
		logger.Warnf("error in storing Registration Response protobuf: %v", err)
		return regResp, err
	}

	return regResp, nil
}
