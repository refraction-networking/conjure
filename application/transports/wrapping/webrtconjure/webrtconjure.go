package webrtconjure

import (
	"bytes"
	"errors"
	"net"

	s2s "github.com/Gaukas/seed2sdp"
	rtc "github.com/Gaukas/transportc"
	webrtc "github.com/pion/webrtc/v3"
	dd "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/transports"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

const WebRTCIdentifierLen = 34 // should be a deterministic number used as key in map[string]*DecoyRegistration

type Transport struct{}

func (Transport) Name() string      { return "TranspoRTC" }
func (Transport) LogPrefix() string { return "WEBRTC" }

// TODO: GetIdentifier
func (Transport) GetIdentifier(r *dd.DecoyRegistration) string {
	return string(r.Keys.SharedSecret) + string(r.Keys.DarkDecoySeed)
}

func (Transport) WrapConnection(data *bytes.Buffer, c net.Conn, phantom net.IP, regManager *dd.RegistrationManager) (*dd.DecoyRegistration, net.Conn, error) {
	// TO-DO: A proper check, or maybe no check. WebRTC does not require a valid c to be passed in anyway...

	// if data.Len() < 32 {
	// 	return nil, nil, transports.ErrTryAgain
	// }

	reg := getWebRTCRegistrations(regManager, phantom)
	if reg == nil {
		return nil, nil, transports.ErrNotTransport
	}
	// if !ok {
	// 	return nil, nil, transports.ErrNotTransport
	// }

	// Collect required info (SDP) from registration.
	// Need:	- Seed, SharedSecret (at least one to be real-time exchanged for security)
	//       	- deflatedSDP
	//		 	- serverIP
	//		 	- serverPort
	// Test: using the first viable registration ONLY.
	var seed string = reg.WebRTCParams.GetRandSeed().GetSeed() // Will error until Protobuf got merged
	var sharedsecret string = reg.WebRTCParams.GetRandSeed().GetSharedSecret()
	var deflatedSDPs []s2s.SDPDeflated
	var pbDeflatedSDPs []*pb.DeflatedSDP = reg.WebRTCParams.GetDeflatedSdps() // Will error until Protobuf got merged
	for _, pbDefSDP := range pbDeflatedSDPs {
		var newSDPDef = s2s.SDPDeflated{
			SDPType:    uint8(pbDefSDP.GetSdpType()),
			IPUpper64:  pbDefSDP.GetIpUpper(),
			IPLower64:  pbDefSDP.GetIpLower(),
			Composed32: pbDefSDP.GetComposedInfo(),
		}
		deflatedSDPs = append(deflatedSDPs, newSDPDef)
	}

	// var serverIP net.IP = phantom
	// var serverPort uint16
	var rawNetConn net.Conn = c // TODO: check if it works
	var rawsocket *net.UDPConn  // Raw UDP Socket, by example a listener.
	rawsocket, ok := rawNetConn.(*net.UDPConn)
	if !ok {
		return nil, nil, transports.ErrNotTransport
	}

	clientSDP, err := InflateSdpWithSeed(seed, sharedsecret, deflatedSDPs)
	if err != nil {
		return nil, nil, err
	}
	InjectAppSpecs(clientSDP)
	clientSDP.AddAttrs(s2s.SDPAttribute{
		Key:   "setup",
		Value: "actpass", // Client always go with server pref
	})

	// Prepare the WebRTConn
	conn, _ := rtc.Dial("udp", "0.0.0.0")
	// err = InitializeWebRTConn(conn, seed, sharedsecret)
	// if err != nil {
	// 	return nil, nil, err
	// }

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
		SelfSDPType:    "answer", // Client: "offer"
		SendBufferSize: rtc.DataChannelBufferSizeDefault,

		//// Shouldn't be needed, if we pass in raw socket.
		// IPAddr: []string{
		// 	serverIP.String(),
		// },
		// Port:          serverPort,
		CandidateType: webrtc.ICECandidateTypeHost,

		RawSocket: rawsocket,
	}
	newSettingEngine := webrtc.SettingEngine{}
	iceParams.InjectSettingEngine(&newSettingEngine)
	// newSettingEngine.SetICEUDPMux(webrtc.NewICEUDPMux(nil, rawsocket))

	newConfiguration := webrtc.Configuration{
		Certificates: []webrtc.Certificate{cert},
		ICEServers: []webrtc.ICEServer{
			{
				// may need to add different/more STUN server for client
				URLs: []string{"stun:stun.l.google.com:19302"},
			},
		},
	}

	err = conn.Init(&newDCConfig, newSettingEngine, newConfiguration)
	if err != nil {
		return nil, nil, err
	}

	conn.SetRemoteSDPJsonString(clientSDP.String())

	// Set Local SDP (answer). Client needs to be able to "guess" a matching one.
	_, err = conn.LocalSDP()
	if err != nil {
		return nil, nil, err
	}

	// Wait for connection establishment
	for (conn.Status() & rtc.WebRTConnReady) == 0 {
		if (conn.Status() & rtc.WebRTConnClosed) == 0 {
			return nil, nil, errors.New("WebRTC Peer Connection Closed.")
		}
		if (conn.Status() & rtc.WebRTConnErrored) == 0 {
			return nil, nil, errors.New("WebRTC Peer Connection Errored.")
		}
	}

	// return reg, transports.PrependToConn(c, data), nil
	return reg, conn, nil
}

// find multiple ones and check each one with net.conn received
func getWebRTCRegistrations(regManager *dd.RegistrationManager, phantom net.IP) *dd.DecoyRegistration {
	// var regs []*dd.DecoyRegistration

	for _, r := range regManager.GetRegistrations(phantom) {
		DeflatedSdps := r.WebRTCParams.GetDeflatedSdps()
		if len(DeflatedSdps) > 0 { // If has any deflated SDP, treat as valid reg
			// regs = append(regs, r)
			return r
		}
	}
	return nil

	// return regs
}
