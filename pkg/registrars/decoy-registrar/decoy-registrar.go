package decoy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/gotapdance/tapdance"
	"github.com/sirupsen/logrus"
)

// Copied from dns-registrar
var (
	ErrRegFailed = errors.New("registration failed")
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
		// r.Send()
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

func (r DecoyRegistrar) Send(ctx context.Context, decoy *pb.TLSDecoySpec, dialErrors chan error) {
	deadline, deadlineAlreadySet := ctx.Deadline()

	if !deadlineAlreadySet {
		deadline = time.Now().Add(tapdance.GetRandomDuration(tapdance.deadlineTCPtoDecoyMin, tapdance.deadlineTCPtoDecoyMax))
	}

	childCtx, childCancelFunc := context.WithDeadline(ctx, deadline)
	defer childCancelFunc()

	//[reference] TCP to decoy
	tcpToDecoyStartTs := time.Now()

	//[Note] decoy.GetIpAddrStr() will get only v4 addr if a decoy has both
	dialConn, err := r.dialContex(childCtx, "tcp", decoy.GetIpAddrStr())

	reg.setTCPToDecoy(tapdance.durationToU32ptrMs(time.Since(tcpToDecoyStartTs)))
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "connect: network is unreachable" {
			dialError <- RegError{msg: err.Error(), code: Unreachable}
			return
		}
		dialError <- err
		return
	}

	//[reference] connection stats tracking
	rtt := rttInt(uint32(time.Since(tcpToDecoyStartTs).Milliseconds()))
	delay := getRandomDuration(1061*rtt*2, 1953*rtt*3) //[TODO]{priority:@sfrolov} why these values??
	TLSDeadline := time.Now().Add(delay)

	tlsToDecoyStartTs := time.Now()
	tlsConn, err := reg.createTLSConn(dialConn, decoy.GetIpAddrStr(), decoy.GetHostname(), TLSDeadline)
	if err != nil {
		dialConn.Close()
		msg := fmt.Sprintf("%v - %v createConn: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		dialError <- RegError{msg: msg, code: TLSError}
		return
	}
	reg.setTLSToDecoy(durationToU32ptrMs(time.Since(tlsToDecoyStartTs)))

	//[reference] Create the HTTP request for the registration
	httpRequest, err := reg.createRequest(tlsConn, decoy)
	if err != nil {
		msg := fmt.Sprintf("%v - %v createReq: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		dialError <- RegError{msg: msg, code: TLSError}
		return
	}

	//[reference] Write reg into conn
	_, err = tlsConn.Write(httpRequest)
	if err != nil {
		// // This will not get printed because it is executed in a goroutine.
		// Logger().Errorf("%v - %v Could not send Conjure registration request, error: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		tlsConn.Close()
		msg := fmt.Sprintf("%v - %v Write: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		dialError <- RegError{msg: msg, code: TLSError}
		return
	}

	dialError <- nil
	readAndClose(dialConn, time.Second*15)
}

// Move to other file eventually?
func GetRandomDuration(base, min, max int) time.Duration {
	addon := getRandInt(min, max) / 1000 // why this min and max???
	rtt := rttInt(reg.getTcpToDecoy())
	return time.Millisecond * time.Duration(base+rtt*addon)
}
