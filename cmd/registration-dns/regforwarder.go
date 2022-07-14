package main

import (
	"bytes"
	"io/ioutil"
	"net/http"

	"github.com/refraction-networking/gotapdance/pkg/dns-registrar/responder"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

// Interface to forward DNS registration requests. Use a dns responder to receive requests and send responses.
type DnsRegForwarder struct {
	// Endpoints to use in registration request
	endpoint   string
	bdendpoint string // bidirectional

	// HTTP clients to use in request
	client *http.Client

	// dns responder to recieve and forward responses with
	dnsResponder *responder.Responder
}

// Create new DnsRegForwarder.
func NewDnsRegForwarder(endpoint string, bdendpoint string, dnsResponder *responder.Responder) (*DnsRegForwarder, error) {
	f := DnsRegForwarder{}

	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	f.client = &http.Client{Transport: httpTransport}

	f.endpoint = endpoint
	f.bdendpoint = bdendpoint
	f.dnsResponder = dnsResponder

	return &f, nil
}

// Define function on how to respond to incoming dns requests and pass it to dnsResponder.
func (f *DnsRegForwarder) RecvAndForward() error {
	// send the raw request payload to the api endpoint and forward its response
	forwardWith := func(reqIn []byte) ([]byte, error) {
		regReq := &pb.C2SWrapper{}
		err := proto.Unmarshal(reqIn, regReq)
		if err != nil {
			log.Infof("Error in recieved request unmarshal: [%v]", err)
			return nil, err
		}

		log.Tracef("Request received: [%+v]", regReq)

		reqIsBd := regReq.GetRegistrationSource() == pb.RegistrationSource_BidirectionalDNS
		if reqIsBd {
			log.Debugf("Received bidirectional request")
		} else {
			log.Debugf("Received unidirectional request")
		}

		log.Debugf("Request ClientConf generation: [%d]", regReq.GetRegistrationPayload().GetDecoyListGeneration())

		log.Debugf("forwarding request to API")
		endpointToUse := f.endpoint
		if reqIsBd {
			endpointToUse = f.bdendpoint
		}

		httpReq, err := http.NewRequest("POST", endpointToUse, bytes.NewReader(reqIn))
		if err != nil {
			log.Errorf("Crafting HTTP request to API failed: %v", err)
			return nil, err
		}

		resp, err := f.client.Do(httpReq)
		if err != nil {
			log.Errorf("Sending HTTP request to API failed: %v", err)
			return nil, err
		}
		defer resp.Body.Close()

		regsuccess := true

		// Check that the HTTP request returned a success code
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			log.Infof("API indicates that registration failed: status code [%d]", resp.StatusCode)
			regsuccess = false
		}

		clientconfOutdated := false
		dnsResp := &pb.DnsResponse{
			Success:            &regsuccess,
			ClientconfOutdated: &clientconfOutdated,
		}

		// if the registration is unidirectional, immediately return
		if regReq.GetRegistrationSource() == pb.RegistrationSource_DNS {
			log.Infof("Unidirectional request successful")
			return proto.Marshal(dnsResp)
		}

		// Read the HTTP response body into []bytes
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("Reading API HTTP response failed: %v", err)
			return nil, err
		}

		regResp := &pb.RegistrationResponse{}
		log.Debugf("API Response length: [%d]", len(bodyBytes))
		err = proto.Unmarshal(bodyBytes, regResp)
		if err != nil {
			log.Errorf("Error in API response unmarshal: %v", err)
			return nil, err
		}

		log.Tracef("API Response: [%+v]", regResp)

		dnsResp.BidirectionalResponse = regResp
		if regResp.GetClientConf() != nil {
			log.Debugf("Removing ClientConf found in response and indicating client ClientConf is outdated")
			regResp.ClientConf = nil
			clientconfOutdated = true
		}

		respPayload, err := proto.Marshal(dnsResp)

		if err != nil {
			log.Infof("Error in DNS registration response marshal: %v", err)
			return nil, err
		}

		log.Infof("Sending DNS registration response to bidirectional request")
		return respPayload, nil
	}

	return f.dnsResponder.RecvAndRespond(forwardWith)
}

// Close the underlying dns responder.
func (f *DnsRegForwarder) Close() error {
	return f.dnsResponder.Close()
}
