package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/mingyech/conjure-dns-registrar/pkg/responder"
)

type DnsRegForwarder struct {
	// Endpoint to use in registration request
	endpoint string

	// HTTP client to use in request
	client *http.Client

	// dns responder to recieve and forward responses with
	dnsResponder *responder.Responder
}

func NewDnsRegForwarder(endpoint string, dnsResponder *responder.Responder) (*DnsRegForwarder, error) {
	f := DnsRegForwarder{}

	t := http.DefaultTransport.(*http.Transport).Clone()
	f.client = &http.Client{Transport: t}

	f.endpoint = endpoint
	f.dnsResponder = dnsResponder

	return &f, nil
}

// define function on how to respond to incoming dns requests and pass it to dnsResponder
func (f *DnsRegForwarder) RecvAndForward() error {
	// send the raw request payload to the api endpoint and forward its response
	forwardWith := func(reqIn []byte) ([]byte, error) {
		log.Println("forwarding request to API")
		httpReq, err := http.NewRequest("POST", f.endpoint, bytes.NewReader(reqIn))
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

		// Read the HTTP response body into []bytes
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		log.Println("forwarding response to client")
		return bodyBytes, nil
	}
	f.dnsResponder.RecvAndRespond(forwardWith)

	return nil
}

func (f *DnsRegForwarder) Close() error {
	return f.dnsResponder.Close()
}
