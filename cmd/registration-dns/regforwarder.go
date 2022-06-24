package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/mingyech/conjure-dns-registrar/pkg/responder"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"google.golang.org/protobuf/proto"
)

type DnsRegForwarder struct {
	// Endpoints to use in registration request
	endpoint   string
	bdendpoint string // bidirectional

	// HTTP clients to use in request
	client *http.Client

	// dns responder to recieve and forward responses with
	dnsResponder *responder.Responder
}

func NewDnsRegForwarder(endpoint string, bdendpoint string, dnsResponder *responder.Responder) (*DnsRegForwarder, error) {
	f := DnsRegForwarder{}

	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	f.client = &http.Client{Transport: httpTransport}

	f.endpoint = endpoint
	f.dnsResponder = dnsResponder

	return &f, nil
}

// define function on how to respond to incoming dns requests and pass it to dnsResponder
func (f *DnsRegForwarder) RecvAndForward() error {
	// send the raw request payload to the api endpoint and forward its response
	forwardWith := func(reqIn []byte) ([]byte, error) {
		regReq := &pb.C2SWrapper{}
		err := proto.Unmarshal(reqIn, regReq)
		if err != nil {
			return nil, err
		}
		log.Printf("ClientConf gen: [%d]", regReq.GetRegistrationPayload().GetDecoyListGeneration())

		reqIsBd := regReq.GetRegistrationSource() == pb.RegistrationSource_BidirectionalDNS
		if reqIsBd {
			log.Println("Request is Bidirectional")
		} else {
			log.Println("Request is unidirectional")
		}

		log.Println("forwarding request to API")
		endpointToUse := f.endpoint
		if reqIsBd {
			endpointToUse = f.bdendpoint
		}

		httpReq, err := http.NewRequest("POST", endpointToUse, bytes.NewReader(reqIn))
		if err != nil {
			return nil, err
		}

		resp, err := f.client.Do(httpReq)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		// Check that the HTTP request returned a success code
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("non-success response code %d from %s", resp.StatusCode, f.endpoint)
		}

		regsuccess := true
		clientconfOutdated := false
		dnsResp := &pb.DnsResponse{
			Success:            &regsuccess,
			ClientconfOutdated: &clientconfOutdated,
		}

		// if the registration is unidirectional, immediately return
		if regReq.GetRegistrationSource() == pb.RegistrationSource_DNS {
			return proto.Marshal(dnsResp)
		}

		// Read the HTTP response body into []bytes
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		regResp := &pb.RegistrationResponse{}
		log.Printf("Response Len: [%d]", len(bodyBytes))
		err = proto.Unmarshal(bodyBytes, regResp)
		if err != nil {
			return nil, err
		}
		dnsResp.BidirectionalResponse = regResp
		if regResp.GetClientConf() != nil {
			log.Printf("Removing ClientConf found in response")
			regResp.ClientConf = nil
			clientconfOutdated = true
		}

		respPayload, err := proto.Marshal(dnsResp)

		if err != nil {
			return nil, err
		}

		log.Println("forwarding response to client")
		return respPayload, nil
	}
	f.dnsResponder.RecvAndRespond(forwardWith)

	return nil
}

func (f *DnsRegForwarder) Close() error {
	return f.dnsResponder.Close()
}
