package conjurertc

import (
	"crypto/sha256"
	"net"
	"os"

	randutil "github.com/Gaukas/randutil_kai"
	s2s "github.com/Gaukas/seed2sdp"
	webrtc "github.com/pion/webrtc/v3"
	"golang.org/x/crypto/hkdf"
)

type webrtcTransport struct {
	DataChannel *s2s.DataChannel
	Seed        string
}

const (
	runesAlpha string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	runesDigit string = "0123456789"

	conjureSecret string = "ConjureConjureConjureConjure"
	clientHKDF    string = "0xBEEF"
	serverHKDF    string = "0xABEE"

	ipHKDF   string = "PHANTOMIP"
	portHKDF string = "PHANTOMPORT"

	lenSeed              = 64
	portLow       int    = 10000
	portHigh      int    = 65535
	txBufferLimit uint64 = 33554432 // Buffer: 32 M
)

func (wt *webrtcTransport) setWebrtcSeed(seed string) {
	wt.Seed = seed
}

func (wt *webrtcTransport) webrtcSeed() (string, error) {
	if len(wt.Seed) != 0 {
		return wt.Seed, nil
	}
	tempSeed, err := randutil.GenerateCryptoRandomString(lenSeed, runesAlpha+runesDigit)
	if err != nil {
		return "", err
	}
	wt.Seed = tempSeed
	return wt.Seed, nil
}

// Select one IP from IPList
func (wt *webrtcTransport) webrtcSelectIP(IPList []net.IP) net.IP {
	seed, _ := wt.webrtcSeed()
	ipReader := hkdf.New(sha256.New, []byte(conjureSecret), []byte(seed), []byte(ipHKDF))
	ipGen := randutil.NewReaderMathRandomGenerator(ipReader)
	return IPList[ipGen.Intn(len(IPList))]
}

// Select port in [low, high)
func (wt *webrtcTransport) webrtcSelectPort(low int, high int) uint16 {
	seed, _ := wt.webrtcSeed()
	portReader := hkdf.New(sha256.New, []byte(conjureSecret), []byte(seed), []byte(portHKDF))
	portGen := randutil.NewReaderMathRandomGenerator(portReader)

	return uint16(low + portGen.Intn(high-low))
}

// TO-DO: Finish callback handlers as a client
func (wt *webrtcTransport) webrtcSetCallbackHandlers() {
	// Called when Peer Connection state changes
	wt.DataChannel.WebRTCPeerConnection.OnICEConnectionStateChange(func(connectionState webrtc.ICEConnectionState) {
		// logger.Printf("Peer Connection changed state to: %s\n", connectionState.String())
		if connectionState.String() == "disconnected" || connectionState.String() == "closed" {
			// logger.Printf("Peer Connection disconnected\n")
			// logger.Printf("Shutting down...\n")
			os.Exit(0)
		}
	})

	// When received the DataChannel created by client
	wt.DataChannel.WebRTCPeerConnection.OnDataChannel(func(d *webrtc.DataChannel) {
		// Called when datachannel is established
		wt.DataChannel.WebRTCDataChannel.OnOpen(func() {
			// logger.Printf("Successfully opened Data Channel '%s'-'%d'. \n", wt.DataChannel.WebRTCDataChannel.Label(), wt.DataChannel.WebRTCDataChannel.ID())
		})

		// Called when receive message from peer
		wt.DataChannel.WebRTCDataChannel.OnMessage(func(msg webrtc.DataChannelMessage) {
			// logger.Printf("%s OnRecv: %d bytes\n", wt.DataChannel.WebRTCDataChannel.Label(), len(msg.Data))
			// TO-DO: Handle the msg.Data as a transport interface
		})

		// Called when Data Channel is closed (by peer)
		wt.DataChannel.WebRTCDataChannel.OnClose(func() {
			// logger.Printf("Data Channel %s closed\n", wt.DataChannel.WebRTCDataChannel.Label())
			// logger.Printf("Tearing down Peer Connection due to closed datachannel\n")
			wt.DataChannel.WebRTCPeerConnection.Close()
		})

		// Called when there is a Data Channel layer error (not peer connection). Safe to tear down connection.
		wt.DataChannel.WebRTCDataChannel.OnError(func(err error) {
			// logger.Printf("[Fatal] Data Channel %s errored: %v\n", wt.DataChannel.WebRTCDataChannel.Label(), err)
			// logger.Printf("Tearing down Peer Connection due to error in datachannel\n")
			wt.DataChannel.WebRTCPeerConnection.Close()
		})
	})
}

// webrtcRegistrationReceived requires ClientSDP (via Registration), seed (via Registration), IPList (shared IP range)
func (wt *webrtcTransport) webrtcRegistrationReceived(ClientSDP s2s.SDPDeflated, seed string, IPList []net.IP) {
	wt.setWebrtcSeed(seed)
	clientHkdfParams := s2s.NewHKDFParams().SetSecret(conjureSecret).SetSalt(seed).SetInfoPrefix(clientHKDF)
	serverHkdfParams := s2s.NewHKDFParams().SetSecret(conjureSecret).SetSalt(seed).SetInfoPrefix(serverHKDF)

	wt.DataChannel = s2s.DeclareDatachannel(
		&s2s.DataChannelConfig{
			Label:          "Conjure DataChannel - Server Side",
			SelfSDPType:    "answer",
			SelfHkdfParams: serverHkdfParams,
			PeerSDPType:    "offer",
			PeerHkdfParams: clientHkdfParams,
			PeerMedias: []s2s.SDPMedia{
				{
					MediaType:   "application",
					Description: "9 UDP/DTLS/SCTP webrtc-datachannel",
				},
			},
			PeerAttributes: []s2s.SDPAttribute{
				{
					Key:   "group",
					Value: "BUNDLE 0",
				},
				{
					Key:   "setup",
					Value: "actpass",
				},
				{
					Key:   "mid",
					Value: "0",
				},
				{
					Value: "sendrecv", // Transceivers
				},
				{
					Key:   "sctp-port",
					Value: "5000",
				},
			},
			TxBufferSize: txBufferLimit,
		},
	)

	// Set IP and Port used
	wt.DataChannel.
		SetIP([]string{wt.webrtcSelectIP(IPList).String()}, s2s.Host).
		SetPort(wt.webrtcSelectPort(portLow, portHigh))

	// Block until DataChannel is created. (Not connecting to any peer yet)
	if wt.DataChannel.Initialize() != nil {
		// Logger().Error("Client failed to initialize a data channel instance.")
		panic("DataChannel.Initialize() unsuccessful.")
	}

	wt.webrtcSetCallbackHandlers()

	// Block until Offer is ready to exchange. (Not connecting to any peer yet)
	if wt.DataChannel.CreateOffer() != nil {
		// Logger().Error("Client failed to create SDP offer.")
		panic("DataChannel.CreateOffer() unsuccessful.")
	}

	offerCandidate := s2s.InflateICECandidateFromSD(ClientSDP)
	err := wt.DataChannel.SetOffer([]s2s.ICECandidate{offerCandidate})
	if err != nil {
		panic(err)
	}

	if wt.DataChannel.CreateAnswer() != nil {
		// fmt.Println("[FATAL] Server failed to create SDP answer.")
		panic("Fatal error.")
	}
	// Finished. Now wait for Client to set "guessed" Answer
}

func (wt *webrtcTransport) webrtcSend(data []byte) {
	for !wt.DataChannel.ReadyToSend() {
		// fmt.Println("[Info] Data Channel not ready...")
	} // Always wait for ready to send
	// Logger().Debugf("Sending %d Bytes via %s\n", len(data), wt.DataChannel.WebRTCDataChannel.Label())
	sendErr := wt.DataChannel.Send(data)
	if sendErr != nil {
		// Logger().Errorf("Error in webrtcSend(), sending %d Bytes unsuccessful.", len(data))
		panic(sendErr)
	}
}
