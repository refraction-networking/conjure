package lib

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/refraction-networking/conjure/pkg/station/log"
)

const proxyStallTimeout = 30 * time.Second
const resetIfNotClosedAfter = 10 // seconds

var (
	// errConnReset replaces the reset error in the halfpipe to remove ips and extra bytes
	errConnReset = errors.New("rst")

	// errConnTimeout replaces the ip.timeout error in the halfpipe to remove ips and extra bytes
	errConnTimeout = errors.New("timeout")

	// replaces refused error to prevent client IP logging
	errConnRefused = errors.New("refused")

	// errUnreachable replaces unreachable error to prevent client IP logging
	errUnreachable = errors.New("unreachable")

	// errConnAborted replaces aborted error to prevent client IP logging
	errConnAborted = errors.New("aborted")
)

func generalizeErr(err error) error {
	switch {
	case err == nil:
		return nil
	case
		errors.Is(err, net.ErrClosed), // Errors indicating operation on something already closed.
		errors.Is(err, io.EOF),
		errors.Is(err, syscall.EPIPE),
		errors.Is(err, os.ErrClosed):
		return nil
	case errors.Is(err, syscall.ECONNRESET):
		return errConnReset
	case errors.Is(err, syscall.ECONNREFUSED):
		return errConnRefused
	case errors.Is(err, syscall.ECONNABORTED):
		return errConnAborted
	case errors.Is(err, syscall.EHOSTUNREACH):
		return errUnreachable
	default:
		if errN, ok := err.(net.Error); ok && errN.Timeout() {
			return errConnTimeout
		}
	}

	// if it is not a well known error, return it
	return err
}

// this function is kinda ugly, uses undecorated logger, and passes things around it doesn't have to
// pass around
func halfPipe(src net.Conn, dst net.Conn,
	wg *sync.WaitGroup,
	logger *log.Logger,
	tag string, stats *tunnelStats) {

	var proxyStartTime = time.Now()
	isUpload := strings.HasPrefix(tag, "Up")

	cleanup := func() {
		// Finalize tunnel stats
		proxyEndTime := time.Since(proxyStartTime)
		stats.duration(int64(proxyEndTime/time.Millisecond), isUpload)
		stats.completed(isUpload)
		wg.Done()
	}
	defer cleanup()

	closeConn := func(c net.Conn, isSrc bool) {
		// If the conn is TCP and close would hang because we have unacknowledged data in the buffer
		// we force the socket to close after 10 seconds. Non-TCP sockets should not have this issue
		cTCP, ok := c.(*net.TCPConn)
		if ok {
			e := cTCP.SetLinger(resetIfNotClosedAfter)
			if eg := generalizeErr(e); eg != nil {
				logger.Errorln("failed to SetLinger: ", eg)
			}
		}

		errConnClose := c.Close()
		if eg := generalizeErr(errConnClose); eg != nil {
			if errors.Is(eg, errConnTimeout) {
				stats.CovertConnErr = eg.Error()
				stats.ClientConnErr = eg.Error()
			} else if isUpload == isSrc { // !(isUpload xor isSource) => connection to covert
				if stats.CovertConnErr == "" {
					stats.CovertConnErr = eg.Error()
				}
			} else { // isUpload xor isSource => connection to client
				if stats.ClientConnErr == "" {
					stats.ClientConnErr = eg.Error()
				}
			}
		}
	}

	defer func() {
		// ensure that neither close blocks on the other
		go closeConn(src, true)
		closeConn(dst, false)
	}()

	// Set deadlines in case either side disappears.
	err := src.SetDeadline(time.Now().Add(proxyStallTimeout))
	if err != nil {
		logger.Errorln("error setting deadline for src conn: ", tag)
		return
	}
	err = dst.SetDeadline(time.Now().Add(proxyStallTimeout))
	if err != nil {
		logger.Errorln("error setting deadline for dst conn: ", tag)
		return
	}

	// using io.CopyBuffer doesn't let us see
	// bytes / second (until very end of connect, then only avg)
	// But io.CopyBuffer is very performant:
	// actually doesn't use a buffer at all, just splices sockets
	// together at the kernel level.
	//
	// We could try to use io.CopyN in a loop or something that
	// gives us occasional bytes. CopyN would not splice, though
	// (uses a LimitedReader that only calls Read)
	//buf := bufferPool.Get().([]byte)
	//written, err := io.CopyBuffer(dst, src, buf)

	// On closer examination, it seems this code below seems about
	// as performant. It's not using splice, but for CO comcast / curveball:
	//				io.CopyBuffer	Read/Write
	// curveball CPU	~2%				~2%
	// DL 40MB time		~11.5s			~11.6s
	// So while io.CopyBuffer is faster, it's not significantly faster

	// If we run into perf problems, we can revert

	buf := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])

			// Update stats:
			stats.addBytes(int64(nw), isUpload)
			if isUpload {
				Stat().AddBytesUp(int64(nw))
			} else {
				Stat().AddBytesDown(int64(nw))
			}

			if ew == nil && nw != nr {
				ew = io.ErrShortWrite
			}

			if ew != nil {
				if e := generalizeErr(ew); e != nil {
					if isUpload {
						stats.CovertConnErr = e.Error()
					} else {
						stats.ClientConnErr = e.Error()
					}
				}
				break
			}

		}
		if er != nil {
			if e := generalizeErr(er); e != nil {
				if isUpload {
					stats.ClientConnErr = e.Error()
				} else {
					stats.CovertConnErr = e.Error()
				}
			}
			break
		}

		// refresh stall timeout - set both because it only happens on write so if connection is
		// sending traffic unidirectionally we prevent the receiving side from timing out.
		err := src.SetDeadline(time.Now().Add(proxyStallTimeout))
		if err != nil {
			logger.Errorln("error setting deadline for src conn: ", tag)
			return
		}
		err = dst.SetDeadline(time.Now().Add(proxyStallTimeout))
		if err != nil {
			logger.Errorln("error setting deadline for dst conn: ", tag)
			return
		}
	}
}

// Proxy take a registration and a net.Conn and forwards client traffic to the
// clients covert destination.
func Proxy(reg *DecoyRegistration, clientConn net.Conn, logger *log.Logger) {

	// New successful connection to station for this registration
	atomic.AddInt64(&reg.tunnelCount, 1)

	tunStats := &tunnelStats{
		proxyStats: getProxyStats(),

		PhantomAddr:    reg.PhantomIp.String(),
		PhantomDstPort: uint(reg.PhantomPort),

		TunnelCount: uint(atomic.LoadInt64(&reg.tunnelCount)),
		ASN:         reg.regASN,
		CC:          reg.regCC,
		Transport:   reg.Transport.String(),
		Registrar:   reg.RegistrationSource.String(),
		V6:          reg.PhantomIp.To4() == nil,
		LibVer:      uint(reg.clientLibVer),
		Gen:         uint(reg.DecoyListVersion),
	}

	paramStrs := (*reg.TransportPtr).ParamStrings(reg.TransportParams)
	if paramStrs != nil {
		tunStats.TransportOpts = paramStrs
	}

	covertConn, err := net.Dial("tcp", reg.Covert)
	if e := generalizeErr(err); e != nil {
		tunStats.CovertDialErr = e.Error()
	}

	// Any common error that is a non-station issue should have covert IP
	// removed.
	if tunStats.CovertDialErr != "" {
		tunStats.Print(logger)
		// logger.Errorf("failed to dial target: %s", err)
		return
	}

	defer covertConn.Close()

	if reg.Flags.GetProxyHeader() {
		err = writePROXYHeader(covertConn, clientConn.RemoteAddr().String())
		if err != nil {
			logger.Errorf("failed to send PROXY header: %s", err)
			return
		}
	}

	wg := sync.WaitGroup{}
	wg.Add(2)

	getProxyStats().addSession()

	go halfPipe(clientConn, covertConn, &wg, logger, "Up "+reg.IDString(), tunStats)
	go halfPipe(covertConn, clientConn, &wg, logger, "Down "+reg.IDString(), tunStats)
	wg.Wait()
	getProxyStats().removeSession()

	tunStats.Print(logger)
}

func writePROXYHeader(conn net.Conn, originalIPPort string) error {

	if len(originalIPPort) == 0 {
		return errors.New("can't write PROXY header: empty IP")
	}
	transportProtocol := "TCP4"
	if !strings.Contains(originalIPPort, ".") {
		transportProtocol = "TCP6"
	}
	host, port, err := net.SplitHostPort(originalIPPort)
	if err != nil {
		return err
	}
	proxyHeader := fmt.Sprintf("PROXY %s %s 127.0.0.1 %s 1234\r\n", transportProtocol, host, port)
	_, err = conn.Write([]byte(proxyHeader))
	return err
}

type tunnelStats struct {
	proxyStats *ProxyStats

	Duration  int64
	BytesUp   int64
	BytesDown int64

	CovertDialErr string
	CovertConnErr string
	ClientConnErr string

	PhantomAddr    string
	PhantomDstPort uint

	TunnelCount   uint
	V6            bool
	ASN           uint   `json:",omitempty"`
	CC            string `json:",omitempty"`
	Transport     string `json:",omitempty"`
	Registrar     string `json:",omitempty"`
	LibVer        uint
	Gen           uint
	TransportOpts []string `json:",omitempty"`
	RegOpts       []string `json:",omitempty"`
	Tags          []string `json:",omitempty"`
}

func (ts *tunnelStats) Print(logger *log.Logger) {
	tunStatsStr, _ := json.Marshal(ts)
	logger.Printf("proxy closed %s", tunStatsStr)
}

func (ts *tunnelStats) completed(isUpload bool) {
	if isUpload {
		ts.proxyStats.addCompleted(ts.BytesUp, isUpload)
	} else {
		ts.proxyStats.addCompleted(ts.BytesDown, isUpload)
	}
}

func (ts *tunnelStats) duration(duration int64, isUpload bool) {
	// only set duration once, so that the first to close gives us the (real) lower bound on tunnel
	// duration.
	if atomic.LoadInt64(&ts.Duration) == 0 {
		atomic.StoreInt64(&ts.Duration, duration)
	}
}

func (ts *tunnelStats) addBytes(n int64, isUpload bool) {
	if isUpload {
		atomic.AddInt64(&ts.BytesUp, n)
	} else {
		atomic.AddInt64(&ts.BytesDown, n)
	}
	ts.proxyStats.addBytes(int64(n), isUpload)
}

// ProxyStats track metrics about byte transfer.
type ProxyStats struct {
	time.Time // epoch start time

	sessionsProxying int64 // Number of open Proxy connections (count - not reset)

	newBytesUp   int64 // Number of bytes transferred during epoch
	newBytesDown int64 // Number of bytes transferred during epoch

	completeBytesUp   int64 // number of bytes transferred through completed connections UP
	completeBytesDown int64 // number of bytes transferred through completed connections DOWN

	zeroByteTunnelsUp   int64 // number of closed tunnels that uploaded 0 bytes
	zeroByteTunnelsDown int64 // number of closed tunnels that downloaded 0 bytes
	completedSessions   int64 // number of completed sessions
}

// PrintAndReset implements the stats interface
func (s *ProxyStats) PrintAndReset(logger *log.Logger) {
	s.printStats(logger)
	s.reset()
}

func (s *ProxyStats) printStats(logger *log.Logger) {
	// prevent div by 0 if thread starvation happens
	var epochDur float64 = math.Max(float64(time.Since(s.Time).Milliseconds()), 1)

	// fmtStr := "proxy-stats: %d (%f/s) up %d (%f/s) down %d completed %d 0up %d 0down  %f avg-non-0-up, %f avg-non-0-down"
	fmtStr := "proxy-stats:%d %d %f %d %f %d %d %d %f %f"

	completedSessions := atomic.LoadInt64(&s.completedSessions)
	zbtu := atomic.LoadInt64(&s.zeroByteTunnelsUp)
	zbtd := atomic.LoadInt64(&s.zeroByteTunnelsDown)

	logger.Infof(fmtStr,
		atomic.LoadInt64(&s.sessionsProxying),
		atomic.LoadInt64(&s.newBytesUp),
		float64(atomic.LoadInt64(&s.newBytesUp))/epochDur*1000,
		atomic.LoadInt64(&s.newBytesDown),
		float64(atomic.LoadInt64(&s.newBytesDown))/epochDur*1000,
		completedSessions,
		zbtu,
		zbtd,
		float64(atomic.LoadInt64(&s.completeBytesUp))/math.Max(float64(completedSessions-zbtu), 1),
		float64(atomic.LoadInt64(&s.completeBytesDown))/math.Max(float64(completedSessions-zbtd), 1),
	)
}

// Reset implements the stats interface
func (s *ProxyStats) Reset() {
	s.reset()
}

func (s *ProxyStats) reset() {
	atomic.StoreInt64(&s.newBytesUp, 0)
	atomic.StoreInt64(&s.newBytesDown, 0)
	atomic.StoreInt64(&s.completeBytesUp, 0)
	atomic.StoreInt64(&s.completeBytesDown, 0)
	atomic.StoreInt64(&s.zeroByteTunnelsUp, 0)
	atomic.StoreInt64(&s.zeroByteTunnelsDown, 0)
	atomic.StoreInt64(&s.completedSessions, 0)
}

func (s *ProxyStats) addSession() {
	atomic.AddInt64(&s.sessionsProxying, 1)
}

func (s *ProxyStats) removeSession() {
	atomic.AddInt64(&s.sessionsProxying, -1)
}

func (s *ProxyStats) addCompleted(nb int64, isUpload bool) {
	if isUpload {
		atomic.AddInt64(&s.completeBytesUp, nb)
		if nb == 0 {
			atomic.AddInt64(&s.zeroByteTunnelsUp, 1)
		}

		// Only add to session count on closed upload stream to prevent double count
		atomic.AddInt64(&s.completedSessions, 1)
	} else {
		atomic.AddInt64(&s.completeBytesDown, nb)
		if nb == 0 {
			atomic.AddInt64(&s.zeroByteTunnelsDown, 1)
		}
	}

}

func (s *ProxyStats) addBytes(nb int64, isUpload bool) {
	if isUpload {
		atomic.AddInt64(&s.newBytesUp, nb)
	} else {
		atomic.AddInt64(&s.newBytesDown, nb)
	}
}

var proxyStatsInstance ProxyStats
var proxyStatsOnce sync.Once

func initProxyStats() {
	proxyStatsInstance = ProxyStats{}
}

// GetProxyStats returns our singleton for proxy stats
func GetProxyStats() *ProxyStats {
	return getProxyStats()
}

// getProxyStats returns our singleton for proxy stats
func getProxyStats() *ProxyStats {
	proxyStatsOnce.Do(initProxyStats)
	return &proxyStatsInstance
}
