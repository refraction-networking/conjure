package tworeqresp

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"

	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
)

type dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

const idLen = 8

type Onerequester interface {
	RequestAndRecv(sendBytes []byte) ([]byte, error)
	Close() error
	SetDialer(dialer dialFunc) error
}

type Requester struct {
	createRequester func() (Onerequester, error)
	mtu             uint
	dialer          dialFunc
}

func NewRequester(createRequester func() (Onerequester, error), mtu uint) (*Requester, error) {
	return &Requester{createRequester: createRequester, mtu: mtu}, nil
}

func (r *Requester) RequestAndRecv(sendBytes []byte) ([]byte, error) {

	id := [idLen]byte{}
	_, err := rand.Read(id[:])
	if err != nil {
		return nil, fmt.Errorf("error generating id: %v", err)
	}

	parts := splitIntoChunks(sendBytes, int(r.mtu))

	resCh := make(chan []byte, len(parts))
	errCh := make(chan error, len(parts))
	waitCh := make(chan struct{}, len(parts))

	for i, partBytes := range parts {
		i := i
		partBytes := partBytes
		go func() {
			toSend := &pb.DnsPartReq{Id: id[:], PartNum: proto.Uint32(uint32(i)), TotalParts: proto.Uint32(uint32(len(parts))), Data: partBytes}
			toSendBytes, err := proto.Marshal(toSend)
			if err != nil {
				errCh <- fmt.Errorf("error marshal part %v: %v", i, err)
				return
			}

			req, err := r.createRequester()
			if err != nil {
				errCh <- fmt.Errorf("error creating requester in part %v: %v", i, err)
				return
			}

			if r.dialer != nil {
				err = req.SetDialer(r.dialer)
				if err != nil {
					errCh <- fmt.Errorf("error setting dialer in part %v: %v", i, err)
					return
				}
			}

			respBytes, err := req.RequestAndRecv(toSendBytes)
			if err != nil {
				errCh <- fmt.Errorf("error request part %v: %v", i, err)
				return
			}

			resp := &pb.DnsPartResp{}
			err = proto.Unmarshal(respBytes, resp)
			if err != nil {
				errCh <- fmt.Errorf("error unmarshal response: %v", err)
				return
			}

			if resp.GetWaiting() {
				waitCh <- struct{}{}
				return
			}

			resCh <- resp.GetData()

		}()
	}

	errs := []error{}

	for range parts {
		select {
		case res := <-resCh:
			return res, nil
		case err = <-errCh:
			errs = append(errs, err)
		case <-waitCh:
		}
	}

	return nil, fmt.Errorf("errors occurred: %v", errs)
}

func splitIntoChunks(data []byte, mtu int) [][]byte {
	var chunks [][]byte

	for i := 0; i < len(data); i += mtu {
		end := min(i+mtu, len(data))

		chunks = append(chunks, data[i:end])
	}

	return chunks
}

// Close closes the parent transport
func (r *Requester) Close() error {
	return nil
}

// SetDialer sets the parent dialer
func (r *Requester) SetDialer(dialer dialFunc) error {
	r.dialer = dialer
	return nil
}
