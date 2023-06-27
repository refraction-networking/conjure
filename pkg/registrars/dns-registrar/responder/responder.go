package responder

import (
	"bytes"
	"encoding/base32"
	"log"
	"net"

	"github.com/flynn/noise"
	"github.com/refraction-networking/conjure/pkg/registrars/dns-registrar/dns"
	"github.com/refraction-networking/conjure/pkg/registrars/dns-registrar/encryption"
	"github.com/refraction-networking/conjure/pkg/registrars/dns-registrar/msgformat"
)

const (
	// How to set the TTL field in Answer resource records.
	responseTTL = 60
)

// base32Encoding is a base32 encoding without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type Responder struct {
	privkey       []byte
	domain        dns.Name
	transport     net.PacketConn
	noiseConfig   noise.Config
	maxUDPPayload int
}

// Decrypt the message and pass it to processMsg, then encrypt and return the response.
func (r *Responder) craftResponse(msg []byte, processMsg func([]byte) ([]byte, error)) ([]byte, error) {
	handshakeState, err := noise.NewHandshakeState(r.noiseConfig)
	if err != nil {
		return nil, err
	}
	payload, sendCipher, _, err := handshakeState.ReadMessage(nil, msg[:])

	if err != nil {
		return nil, err
	}

	responseBytes, err := processMsg(payload)
	if err != nil {
		return nil, err
	}

	response, err := sendCipher.Encrypt(nil, nil, responseBytes)

	return response, err

}

// responseFor constructs a response dns.Message that is appropriate for query.
// Along with the dns.Message, it returns the query's decoded data payload. If
// the returned dns.Message is nil, it means that there should be no response to
// this query. If the returned dns.Message has an Rcode() of dns.RcodeNoError,
// the message is a candidate for for carrying downstream data in a TXT record.
func (r *Responder) responseFor(query *dns.Message, domain dns.Name) (*dns.Message, []byte) {
	resp := &dns.Message{
		ID:       query.ID,
		Flags:    0x8000, // QR = 1, RCODE = no error
		Question: query.Question,
	}

	if query.Flags&0x8000 != 0 {
		// QR != 0, this is not a query. Don't even send a response.
		return nil, nil
	}

	// Check for EDNS(0) support. Include our own OPT RR only if we receive
	// one from the requester.
	// https://tools.ietf.org/html/rfc6891#section-6.1.1
	// "Lack of presence of an OPT record in a request MUST be taken as an
	// indication that the requester does not implement any part of this
	// specification and that the responder MUST NOT include an OPT record
	// in its response."
	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a query message with more than one OPT RR is
			// received, a FORMERR (RCODE=1) MUST be returned."
			resp.Flags |= dns.RcodeFormatError
			log.Printf("FORMERR: more than one OPT RR")
			return resp, nil
		}
		resp.Additional = append(resp.Additional, dns.RR{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: 4096, // responder's UDP payload size
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]

		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			// https://tools.ietf.org/html/rfc6891#section-6.1.1
			// "If a responder does not implement the VERSION level
			// of the request, then it MUST respond with
			// RCODE=BADVERS."
			resp.Flags |= dns.ExtendedRcodeBadVers & 0xf
			additional.TTL = (dns.ExtendedRcodeBadVers >> 4) << 24
			log.Printf("BADVERS: EDNS version %d != 0", version)
			return resp, nil
		}

		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		// https://tools.ietf.org/html/rfc6891#section-6.1.1 "Values
		// lower than 512 MUST be treated as equal to 512."
		payloadSize = 512
	}
	// We will return RcodeFormatError if payloadSize is too small, but
	// first, check the name in order to set the AA bit properly.

	// There must be exactly one question.
	if len(query.Question) != 1 {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: too few or too many questions (%d)", len(query.Question))
		return resp, nil
	}
	question := query.Question[0]
	// Check the name to see if it ends in our chosen domain, and extract
	// all that comes before the domain if it does. If it does not, we will
	// return RcodeNameError below, but prefer to return RcodeFormatError
	// for payload size if that applies as well.
	prefix, ok := question.Name.TrimSuffix(domain)
	if !ok {
		// Not a name we are authoritative for.
		resp.Flags |= dns.RcodeNameError
		log.Printf("NXDOMAIN: not authoritative for %s", question.Name)
		return resp, nil
	}
	resp.Flags |= 0x0400 // AA = 1

	if query.Opcode() != 0 {
		// We don't support OPCODE != QUERY.
		resp.Flags |= dns.RcodeNotImplemented
		log.Printf("NOTIMPL: unrecognized OPCODE %d", query.Opcode())
		return resp, nil
	}

	if question.Type != dns.RRTypeTXT {
		// We only support QTYPE == TXT.
		resp.Flags |= dns.RcodeNameError
		// No log message here; it's common for recursive resolvers to
		// send NS or A queries when the client only asked for a TXT. I
		// suspect this is related to QNAME minimization, but I'm not
		// sure. https://tools.ietf.org/html/rfc7816
		// log.Printf("NXDOMAIN: QTYPE %d != TXT", question.Type)
		return resp, nil
	}

	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		// Base32 error, make like the name doesn't exist.
		resp.Flags |= dns.RcodeNameError
		log.Printf("NXDOMAIN: base32 decoding: %v", err)
		return resp, nil
	}
	payload = payload[:n]

	// We require clients to support EDNS(0) with a minimum payload size;
	// otherwise we would have to set a small KCP MTU (only around 200
	// bytes). https://tools.ietf.org/html/rfc6891#section-7 "If there is a
	// problem with processing the OPT record itself, such as an option
	// value that is badly formatted or that includes out-of-range values, a
	// FORMERR MUST be returned."
	if payloadSize < r.maxUDPPayload {
		resp.Flags |= dns.RcodeFormatError
		log.Printf("FORMERR: requester payload size %d is too small (minimum %d)", payloadSize, r.maxUDPPayload)
		return resp, nil
	}

	return resp, payload
}

// recvLoop repeatedly calls dnsConn.ReadFrom, extracts the packets contained in
// the incoming DNS queries, and puts them on ttConn's incoming queue. Whenever
// a query calls for a response, constructs a partial response and passes it to
// sendLoop over ch.
func (r *Responder) RecvAndRespond(getResponse func([]byte) ([]byte, error)) error {
	for {
		var buf [4096]byte
		n, addr, err := r.transport.ReadFrom(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok {
				log.Printf("ReadFrom error: %v", err)
				continue
			}
			return err
		}

		// Parse message and respond
		go func() {
			// Got a UDP packet. Try to parse it as a DNS message.
			query, err := dns.MessageFromWireFormat(buf[:n])
			if err != nil {
				log.Printf("cannot parse DNS query: %v", err)
			}

			resp, payload := r.responseFor(&query, r.domain)
			if resp == nil {
				return
			}

			var responseBuf []byte

			// invalid msg if returned payload is empty, do not process
			if payload != nil {
				payload, err = msgformat.RemoveRequestFormat(payload)
				if err != nil {
					log.Printf("RemoveFormat err: %v", err)
					return
				}

				responseBuf, err = r.craftResponse(payload, getResponse)
				if err != nil {
					log.Printf("craftResponse err: %v", err)
					return
				}

				responseBuf, err = msgformat.AddResponseFormat(responseBuf)
				if err != nil {
					log.Printf("AddFormat err: %v", err)
					return
				}
			}

			responsePayload, err := r.dnsRespToUDPResp(resp, responseBuf)
			if err != nil {
				log.Printf("dnsRespToUDPResp err: %v", err)
				return
			}

			if len(responsePayload) > r.maxUDPPayload {
				log.Printf("ERR: Response UDP payload length [%d] exceed maxUDPPayload size [%d], responding with empty response.", len(responsePayload), r.maxUDPPayload)
				responsePayload, err = r.dnsRespToUDPResp(resp, []byte{})
				if err != nil {
					log.Printf("dnsRespToUDPResp err: %v", err)
					return
				}
			}

			_, err = r.transport.WriteTo(responsePayload, addr)
			if err != nil {
				log.Printf("WriteTo err: %v", err)
			}
		}()
	}
}

// Put response payload into DNS answer ready to send
func (r *Responder) dnsRespToUDPResp(resp *dns.Message, response []byte) ([]byte, error) {
	if resp.Rcode() == dns.RcodeNoError && len(resp.Question) == 1 {
		// If it's a non-error response, we can fill the Answer
		// section with downstream packets.

		// Any changes to how responses are built need to happen
		// also in computeMaxEncodedPayload.
		resp.Answer = []dns.RR{
			{
				Name:  resp.Question[0].Name,
				Type:  resp.Question[0].Type,
				Class: resp.Question[0].Class,
				TTL:   responseTTL,
				Data:  nil, // will be filled in below
			},
		}

		resp.Answer[0].Data = dns.EncodeRDataTXT(response)
	}

	buf, err := resp.WireFormat()
	if err != nil {
		log.Printf("resp WireFormat: %v", err)
		return nil, err
	}

	return buf, nil
}

func NewDnsResponder(domain string, listenAddr string, privkey []byte) (*Responder, error) {
	noiseConfig := encryption.NewConfig()
	noiseConfig.Initiator = false
	noiseConfig.StaticKeypair = noise.DHKey{
		Private: privkey,
		Public:  encryption.PubkeyFromPrivkey(privkey),
	}

	basename, err := dns.ParseName(domain)
	if err != nil {
		return nil, err
	}

	dnsConn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return nil, err
	}

	// We don't send UDP payloads larger than this, in an attempt to avoid
	// network-layer fragmentation. 1280 is the minimum IPv6 MTU, 40 bytes
	// is the size of an IPv6 header (though without any extension headers),
	// and 8 bytes is the size of a UDP header.
	//
	// https://dnsflagday.net/2020/#message-size-considerations
	// "An EDNS buffer size of 1232 bytes will avoid fragmentation on nearly
	// all current networks."
	//
	// On 2020-04-19, the Quad9 resolver was seen to have a UDP payload size
	// of 1232. Cloudflare's was 1452, and Google's was 4096.
	maxUDPPayload := 1280 - 40 - 8

	return &Responder{
		domain:        basename,
		transport:     dnsConn,
		privkey:       privkey,
		noiseConfig:   noiseConfig,
		maxUDPPayload: maxUDPPayload,
	}, nil
}

func (r *Responder) Close() error {
	return r.transport.Close()
}
