package lib

// Note: This file might not be necessary.

const (
	ConjureDevSeed          string = "conjureconjureconjureconjure"
	DefaultOfferIdentifier  string = "reffO"
	DefaultAnswerIdentifier string = "rewsnA"
)

type WebRTCIdentifier struct {
	Offer  string
	Answer string
}

type WebRTCCryptoParams struct {
	SharedSecret string
	ID           WebRTCIdentifier
	ConnSeed     string
}

func newWebRTCCryptoParams(seed, sharedSecret string) WebRTCCryptoParams {
	return WebRTCCryptoParams{
		SharedSecret: sharedSecret,
		ID: WebRTCIdentifier{
			Offer:  DefaultOfferIdentifier,
			Answer: DefaultAnswerIdentifier,
		},
		ConnSeed: seed,
	}
}
