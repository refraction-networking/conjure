package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"

	"github.com/refraction-networking/gotapdance/pkg/dns-registrar/responder"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// DnsRegForwarder provides an interface to forward DNS registration requests. Use a dns responder to receive requests and send responses.
type DnsRegForwarder struct {
	// Endpoints to use in registration request
	endpoint   string
	bdendpoint string // bidirectional

	// HTTP clients to use in request
	client *http.Client

	// dns responder to recieve and forward responses with
	dnsResponder *responder.Responder
}

// NewDnsRegForwarder initializes a new DnsRegForwarder object.
func NewDnsRegForwarder(endpoint string, bdendpoint string, dnsResponder *responder.Responder) (*DnsRegForwarder, error) {
	f := DnsRegForwarder{}

	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	f.client = &http.Client{Transport: httpTransport}

	f.endpoint = endpoint
	f.bdendpoint = bdendpoint
	f.dnsResponder = dnsResponder

	return &f, nil
}

// RecvAndForward defines a function on how to respond to incoming dns requests and pass it to dnsResponder.
func (f *DnsRegForwarder) RecvAndForward() error {

	// send the raw request payload to the api endpoint and forward its response
	forwardWith := func(reqIn []byte) ([]byte, error) {
		regReq := &pb.C2SWrapper{}
		err := proto.Unmarshal(reqIn, regReq)
		if err != nil {
			log.Errorf("Error in recieved request unmarshal: [%v]", err)
			return nil, err
		}

		reqLogger := log.WithField("RegID", hex.EncodeToString(regReq.GetSharedSecret()))

		reqLogger.Tracef("Request received: [%+v]", regReq)

		reqIsBd := regReq.GetRegistrationSource() == pb.RegistrationSource_BidirectionalDNS
		if reqIsBd {
			reqLogger.Debugf("Received bidirectional request")
		} else {
			reqLogger.Debugf("Received unidirectional request")
		}

		reqLogger.Debugf("Request ClientConf generation: [%d]", regReq.GetRegistrationPayload().GetDecoyListGeneration())

		reqLogger.Debugf("forwarding request to API")
		endpointToUse := f.endpoint
		if reqIsBd {
			endpointToUse = f.bdendpoint
		}

		httpReq, err := http.NewRequest("POST", endpointToUse, bytes.NewReader(reqIn))
		if err != nil {
			reqLogger.Errorf("Crafting HTTP request to API failed: %v", err)
			return nil, err
		}

		resp, err := f.client.Do(httpReq)
		if err != nil {
			reqLogger.Errorf("Sending HTTP request to API failed: %v", err)
			return nil, err
		}
		defer resp.Body.Close()

		regsuccess := true
		clientconfOutdated := false
		dnsResp := &pb.DnsResponse{
			Success:            &regsuccess,
			ClientconfOutdated: &clientconfOutdated,
		}

		// Check that the HTTP request returned a success code
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			reqLogger.Errorf("Registration unsuccessful: HTTP API status code [%d]", resp.StatusCode)
			regsuccess = false
			return proto.Marshal(dnsResp)
		}

		// if the registration is unidirectional, immediately return
		if regReq.GetRegistrationSource() == pb.RegistrationSource_DNS {
			reqLogger.Infof("Unidirectional request successful")
			return proto.Marshal(dnsResp)
		}

		// Read the HTTP response body into []bytes
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			reqLogger.Errorf("Reading API HTTP response failed: [%v]", err)
			return nil, err
		}

		regResp := &pb.RegistrationResponse{}
		reqLogger.Debugf("API Response length: [%d]", len(bodyBytes))
		err = proto.Unmarshal(bodyBytes, regResp)
		if err != nil {
			reqLogger.Errorf("Error in API response unmarshal: [%v]", err)
			return nil, err
		}

		reqLogger.Tracef("API Response: [%+v]", regResp)

		dnsResp.BidirectionalResponse = regResp
		if regResp.GetClientConf() != nil {
			reqLogger.Debugf("Removing ClientConf found in response and indicating client ClientConf is outdated")
			regResp.ClientConf = nil
			clientconfOutdated = true
		}

		respPayload, err := proto.Marshal(dnsResp)

		if err != nil {
			reqLogger.Errorf("Error in DNS registration response marshal: [%v]", err)
			return nil, err
		}

		reqLogger.Infof("Bidirectional request successful")
		return respPayload, nil
	}

	return f.dnsResponder.RecvAndRespond(forwardWith)
}

// Close closes the underlying dns responder.
func (f *DnsRegForwarder) Close() error {
	return f.dnsResponder.Close()
}
