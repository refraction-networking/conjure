package webrtconjure

import (
	"net"

	s2s "github.com/Gaukas/seed2sdp"
)

const (
	ServerClientSharedSecret string = "A VERY LONG AND STRONG SECRET"
	OffererIdentifier        string = "reffO"
	AnswererIdentifier       string = "rewsnA"
)

const (
	ConjureDevSeed          string = "conjureconjureconjureconjure"
	ConjureDevSharedSecret  string = "Shared Secret. Tell nobody!!"
	DefaultOfferIdentifier  string = "reffO"
	DefaultAnswerIdentifier string = "rewsnA"
)

func getServerHkdfParams(seed, sharedSecret string) *s2s.HKDFParams {
	return s2s.NewHKDFParams().SetSecret(sharedSecret).SetInfoPrefix(AnswererIdentifier).SetSalt(seed)
}

func getClientHkdfParams(seed, sharedSecret string) *s2s.HKDFParams {
	return s2s.NewHKDFParams().SetSecret(sharedSecret).SetInfoPrefix(OffererIdentifier).SetSalt(seed)
}

func InflateSdpWithSeed(seed, sharedSecret string, deflatedSDP []s2s.SDPDeflated) (*s2s.SDP, error) {
	// Debug: Server always as Answerer. Thus, Inflate with OffererIdentifier (due to peer's identity: Offerer).
	var hkdfParams *s2s.HKDFParams = getClientHkdfParams(seed, sharedSecret)
	// hkdfParams = &s2s.NewHKDFParams().SetSecret(ServerClientSharedSecret).SetInfoPrefix(AnswererIdentifier)

	sdp, err := s2s.GroupInflate(deflatedSDP)
	if err != nil {
		return nil, err
	}

	sdp.Fingerprint, err = s2s.PredictDTLSFingerprint(hkdfParams) // The deterministic fingerprint from the seed
	if err != nil {
		return nil, err
	}

	sdp.IceParams, err = s2s.PredictIceParameters(hkdfParams) // The deterministic
	if err != nil {
		return nil, err
	}

	sdp.Malleables = s2s.PredictSDPMalleables(hkdfParams) // It is temporarily hardcoded. Could be revisited in later versions.

	return sdp, nil
}

// CreateSdpWithSeed() predicts an Answer. Answer Only!!
func CreateSdpWithSeed(seed, sharedSecret string, serverHostIP net.IP, serverPort uint16) (*s2s.SDP, error) {
	var err error
	hkdfParams := s2s.NewHKDFParams().SetSecret(sharedSecret).SetInfoPrefix(AnswererIdentifier).SetSalt(seed)

	rtpCandidate := s2s.ICECandidate{}
	rtpCandidate.SetComponent(s2s.ICEComponentRTP)
	rtpCandidate.SetProtocol(s2s.UDP)
	rtpCandidate.SetIpAddr(serverHostIP)
	rtpCandidate.SetPort(serverPort)
	rtpCandidate.SetCandidateType(s2s.Host)

	rtcpCandidate := s2s.ICECandidate{}
	rtcpCandidate.SetComponent(s2s.ICEComponentRTCP)
	rtcpCandidate.SetProtocol(s2s.UDP)
	rtcpCandidate.SetIpAddr(serverHostIP)
	rtcpCandidate.SetPort(serverPort)
	rtcpCandidate.SetCandidateType(s2s.Host)

	sdp := s2s.SDP{
		SDPType:    "answer", // Assume server is the answerer, as usual
		Malleables: s2s.PredictSDPMalleables(hkdfParams),
		IceCandidates: []s2s.ICECandidate{
			rtpCandidate,
			rtcpCandidate,
		},
	}

	sdp.Fingerprint, err = s2s.PredictDTLSFingerprint(hkdfParams) // The deterministic fingerprint from the seed
	if err != nil {
		return nil, err
	}

	sdp.IceParams, err = s2s.PredictIceParameters(hkdfParams) // The deterministic
	if err != nil {
		return nil, err
	}

	return &sdp, nil
}

//
func InjectAppSpecs(sdp *s2s.SDP) {
	// m-line
	sdp.AddMedia(s2s.SDPMedia{
		MediaType:   "application",
		Description: "9 UDP/DTLS/SCTP webrtc-datachannel",
	})

	// a-lines, except for fingerprint, candidate. ice-ufrag, ice-pwd
	sdp.AddAttrs(s2s.SDPAttribute{
		Key:   "group",
		Value: "BUNDLE 0",
	})

	// for a=setup, we will need to treat server and client differently.
	// sdp.AddAttrs(s2s.SDPAttribute{
	// 	Key: "setup",
	// 	// Value: "active", // Uncomment this line, if server calls SetDTLSActive() or by default
	// 	// Value: "passive", // Uncomment this line, if server calls SetDTLSPassive()
	// })

	sdp.AddAttrs(s2s.SDPAttribute{
		Key:   "mid",
		Value: "0",
	})

	sdp.AddAttrs(s2s.SDPAttribute{
		Value: "sendrecv",
	})

	sdp.AddAttrs(s2s.SDPAttribute{
		Key:   "sctp-port",
		Value: "5000",
	})
}
