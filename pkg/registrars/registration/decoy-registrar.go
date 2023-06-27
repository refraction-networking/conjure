package registration

import (
	"context"
	"net"

	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/gotapdance/tapdance"
	"github.com/sirupsen/logrus"
)

type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type DecoyRegistrar struct {

	// dialContex is a custom dailer to use when establishing TCP connections
	// to decoys. When nil, Dialer.dialContex will be used.
	dialContex DialFunc

	logger logrus.FieldLogger
}

func NewDecoyRegistrar() *DecoyRegistrar {
	return &DecoyRegistrar{
		logger: tapdance.Logger(),
	}
}

func NewDecoyRegistrarWithDialer(dialer DialFunc) *DecoyRegistrar {
	return &DecoyRegistrar{
		dialContex: dialer,
		logger:     tapdance.Logger(),
	}
}

func (r DecoyRegistrar) Register(cjSession *tapdance.ConjureSession, ctx context.Context) (*tapdance.ConjureReg, error) {
	logger := r.logger.WithFields(logrus.Fields{"type": "unidirectional", "sessionID": cjSession.IDString()})

	logger.Debugf("Registering V4 and V6 via DecoyRegistrar")

	reg, _, err := cjSession.UnidirectionalRegData(pb.RegistrationSource_API.Enum())
	if err != nil {
		logger.Errorf("Failed to prepare registration data: %v", err)
		return nil, ErrRegFailed
	}

	// Choose N (width) decoys from decoylist
	decoys, err := cjSession.Decoys()
	if err != nil {
		logger.Warnf("failed to select decoys: %v", err)
		return nil, err
	}

	if r.dialContex != nil {
		reg.Dialer = r.dialContex
	}

	// //[TODO]{priority:later} How to pass context to multiple registration goroutines?
	if ctx == nil {
		ctx = context.Background()
	}

	width := uint(len(decoys))
	if width < cjSession.Width {
		logger.Warnf("Using width %v (default %v)", width, cjSession.Width)
	}

	//[reference] Send registrations to each decoy
	dialErrors := make(chan error, width)
	for _, decoy := range decoys {
		logger.Debugf("Sending Reg: %v, %v", decoy.GetHostname(), decoy.GetIpAddrStr())
		//decoyAddr := decoy.GetIpAddrStr()
		go reg.Send(ctx, decoy, dialErrors)
	}

	//[reference] Dial errors happen immediately so block until all N dials complete
	var unreachableCount uint = 0
	for err := range dialErrors {
		if err != nil {
			logger.Debugf("%v", err)
			if dialErr, ok := err.(tapdance.RegError); ok && dialErr.Code() == tapdance.Unreachable {
				// If we failed because ipv6 network was unreachable try v4 only.
				unreachableCount++
				if unreachableCount < width {
					continue
				} else {
					break
				}
			}
		}
		//[reference] if we succeed or fail for any other reason then the network is reachable and we can continue
		break
	}

	//[reference] if ALL fail to dial return error (retry in parent if ipv6 unreachable)
	if unreachableCount == width {
		logger.Debugf("NETWORK UNREACHABLE")
		return nil, tapdance.NewRegError(tapdance.Unreachable, "All decoys failed to register -- Dial Unreachable")
	}

	// randomized sleeping here to break the intraflow signal
	toSleep := reg.GetRandomDuration(3000, 212, 3449)
	logger.Debugf("Successfully sent registrations, sleeping for: %v", toSleep)
	sleepWithContext(ctx, toSleep)

	return reg, nil
}
