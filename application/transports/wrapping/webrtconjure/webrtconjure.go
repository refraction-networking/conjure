package webrtconjure

import (
	"bytes"
	"net"

	s2s "github.com/Gaukas/seed2sdp"
	rtc "github.com/Gaukas/transportc"
	"github.com/pion/webrtc/v3"
	dd "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/transports"
)

const WebRTCIdentifierLen = 34 // should be a deterministic number used as key in map[string]*DecoyRegistration

type Transport struct{}

func (Transport) Name() string      { return "TranspoRTC" }
func (Transport) LogPrefix() string { return "WEBRTC" }

func (Transport) GetIdentifier(r *dd.DecoyRegistration) string {
	return string(r.Keys.SharedSecret) + string(r.Keys.DarkDecoySeed)
}

func (Transport) WrapConnection(data *bytes.Buffer, c net.Conn, phantom net.IP, regManager *dd.RegistrationManager) (*dd.DecoyRegistration, net.Conn, error) {
	// TO-DO: A proper check, or maybe no check. WebRTC does not reuse c passed in.

	// if data.Len() < 32 {
	// 	return nil, nil, transports.ErrTryAgain
	// }

	hmacID := string(data.Bytes()[:32])
	reg, ok := regManager.GetRegistrations(phantom)[hmacID]
	if !ok {
		return nil, nil, transports.ErrNotTransport
	}

	// TO-DO: Collect required info (SDP) from registration.
	// Need:	- Seed, SharedSecret (at least one to be real-time exchanged for security)
	//       	- deflatedSDP
	//		 	- serverIP
	//		 	- serverPort
	var seed string
	var sharedsecret string
	var deflatedSDP s2s.SDPDeflated
	var serverIP net.IP
	var serverPort uint16

	clientSDP, err := InflateSdpWithSeed(seed, sharedsecret, deflatedSDP)
	if err != nil {
		return nil, nil, err
	}
	InjectAppSpecs(clientSDP)
	clientSDP.AddAttrs(s2s.SDPAttribute{
		Key:   "setup",
		Value: "actpass",
	})

	// Prepare the WebRTConn
	conn, _ := rtc.Dial("udp", "0.0.0.0")
	err = InitializeWebRTConn(conn, seed, sharedsecret)
	if err != nil {
		return nil, nil, err
	}

	// Build transportc config, pion SettingEngine, pion Configuration
	serverHkdfParams := getServerHkdfParams(seed, sharedsecret)
	cert, err := s2s.GetCertificate(serverHkdfParams)
	if err != nil {
		return nil, nil, err
	}
	iceParams, err := s2s.PredictIceParameters(serverHkdfParams)
	if err != nil {
		return nil, nil, err
	}

	newDCConfig := rtc.DataChannelConfig{
		Label:          "Seed2WebRTConn Server",
		SelfSDPType:    "answer",
		SendBufferSize: rtc.DataChannelBufferSizeDefault,

		IPAddr: []string{
			serverIP.String(),
		},
		CandidateType: webrtc.ICECandidateTypeHost,
		Port:          serverPort,
	}
	newSettingEngine := webrtc.SettingEngine{}
	iceParams.UpdateSettingEngine(&newSettingEngine)

	newConfiguration := webrtc.Configuration{
		Certificates: []webrtc.Certificate{cert},
		ICEServers: []webrtc.ICEServer{
			{
				URLs: []string{"stun:stun.l.google.com:19302"},
			},
		},
	}

	err = conn.Init(&newDCConfig, newSettingEngine, newConfiguration)
	if err != nil {
		return nil, nil, err
	}

	conn.SetRemoteSDPJsonString(clientSDP.String())

	// Set Local SDP (answer). Client should be able to approximate a matching one.
	_, err = conn.LocalSDP()
	if err != nil {
		return nil, nil, err
	}

	// Wait for connection establishment
	for (conn.Status() & rtc.WebRTConnReady) == 0 {
	}

	return reg, transports.PrependToConn(c, data), nil
}

func getWebRTCRegistrations(regManager *dd.RegistrationManager, phantom net.IP) []*dd.DecoyRegistration {
	var regs []*dd.DecoyRegistration

	for identifier, r := range regManager.GetRegistrations(phantom) {
		if len(identifier) == WebRTCIdentifierLen { // Fix this Length check, or use other checking
			regs = append(regs, r)
		}
	}

	return regs
}
