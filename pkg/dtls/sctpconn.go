package dtls

import (
	"fmt"
	"net"
	"time"

	"github.com/pion/logging"
	"github.com/pion/sctp"
)

// SCTPConn implements the net.Conn interface using sctp stream and DTLS conn
type SCTPConn struct {
	stream *sctp.Stream
	conn   net.Conn
}

func newSCTPConn(stream *sctp.Stream, conn net.Conn) *SCTPConn {
	return &SCTPConn{stream: stream, conn: conn}
}

func (s *SCTPConn) Close() error {
	err := s.stream.Close()
	if err != nil {
		return err
	}
	return s.conn.Close()
}

func (s *SCTPConn) Write(b []byte) (int, error) {
	return s.stream.Write(b)
}

func (s *SCTPConn) Read(b []byte) (int, error) {
	return s.stream.Read(b)
}

func (s *SCTPConn) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *SCTPConn) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

func (s *SCTPConn) SetDeadline(t time.Time) error {
	return s.conn.SetDeadline(t)
}

func (s *SCTPConn) SetWriteDeadline(t time.Time) error {
	return s.conn.SetWriteDeadline(t)
}

func (s *SCTPConn) SetReadDeadline(t time.Time) error {
	return s.stream.SetReadDeadline(t)
}

func openSCTP(conn net.Conn) (net.Conn, error) {
	// Start SCTP
	sctpConf := sctp.Config{
		NetConn:       conn,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	}

	sctpClient, err := sctp.Client(sctpConf)

	if err != nil {
		return nil, fmt.Errorf("error creating sctp client: %v", err)
	}

	sctpStream, err := sctpClient.OpenStream(0, sctp.PayloadTypeWebRTCString)

	if err != nil {
		return nil, fmt.Errorf("error setting up stream: %v", err)
	}

	sctpConn := newSCTPConn(sctpStream, conn)

	err = heartbeatClient(sctpConn, nil)
	if err != nil {
		return nil, fmt.Errorf("error opening heartbeat client: %v", err)
	}

	return sctpConn, nil
}

func acceptSCTP(conn net.Conn) (net.Conn, error) {

	// Start SCTP over DTLS connection
	sctpConfig := sctp.Config{
		NetConn:       conn,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	}

	sctpServer, err := sctp.Server(sctpConfig)
	if err != nil {
		return nil, err
	}

	sctpStream, err := sctpServer.AcceptStream()
	if err != nil {
		return nil, err
	}

	sctpConn := newSCTPConn(sctpStream, conn)

	heartbeatConn, err := heartbeatServer(sctpConn, nil)
	if err != nil {
		return nil, fmt.Errorf("error starting heartbeat server: %v", err)
	}

	return heartbeatConn, nil

}

func wrapSCTP(conn net.Conn, config *Config) (net.Conn, error) {
	if config.SCTP == ServerAccept {
		return acceptSCTP(conn)
	}

	return openSCTP(conn)
}
