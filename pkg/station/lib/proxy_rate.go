package lib

import (
	"errors"
	"io"

	"github.com/refraction-networking/conjure/pkg/station/log"
)

type direction int

const (
	up direction = iota
	down
)

func isUploadDir(b bool) direction {
	if b {
		return up
	}
	return down
}

type rateWrapper struct {
	r           io.Reader
	tunnelStats *tunnelStats
	sharedStats *Stats
	d           direction
	nonZeroHook func()
	desc        string
}

func newRater(r io.Reader, ts *tunnelStats, s *Stats, dir direction) *rateWrapper {
	rd := &rateWrapper{
		r:           r,
		tunnelStats: ts,
		sharedStats: s,
	}
	return rd
}

func (r *rateWrapper) Read(c []byte) (n int, err error) {
	if r == nil || r.r == nil {
		return 0, errNotExist
	}

	n, err = r.r.Read(c)
	log.Tracef("%s - Read %d bytes, %s", r.desc, n, err)

	if n == 0 {
		return
	}

	if r.tunnelStats != nil {
		r.tunnelStats.addBytes(int64(n), r.d == up)
	}

	if r.sharedStats != nil {
		if r.d == up {
			r.sharedStats.AddBytesUp(int64(n))
		} else {
			r.sharedStats.AddBytesDown(int64(n))
		}
	}

	if r.nonZeroHook != nil {
		r.nonZeroHook()
	}

	return
}

var errNotExist = errors.New("does not exist")

type errWrapper struct {
	r io.Reader
	w io.Writer

	tunnelStats *tunnelStats
	d           direction
	desc        string
}

func newReadErrWrapper(r io.Reader, ts *tunnelStats, dir direction) *errWrapper {
	return &errWrapper{
		r:           r,
		tunnelStats: ts,
	}
}

func newWriteErrWrapper(w io.Writer, ts *tunnelStats, dir direction) *errWrapper {
	return &errWrapper{
		w:           w,
		tunnelStats: ts,
	}
}

func (r *errWrapper) Read(c []byte) (n int, err error) {
	if r == nil || r.r == nil {
		return 0, errNotExist
	}

	n, err = r.r.Read(c)

	if err != nil {
		if e := generalizeErr(err); e != nil {
			log.Tracef("%s - Read error: %s = %s", r.desc, err, e)
			if r.d == up {
				r.tunnelStats.ClientConnErr = e.Error()
			} else {
				r.tunnelStats.CovertConnErr = e.Error()
			}
		}
	}

	return
}

func (r *errWrapper) Write(c []byte) (n int, err error) {
	if r == nil || r.w == nil {
		return 0, errNotExist
	}

	n, err = r.w.Write(c)

	if err != nil {
		if e := generalizeErr(err); e != nil {
			log.Tracef("%s - Write error: %s = %s", r.desc, err, e)
			if r.d == up {
				r.tunnelStats.CovertConnErr = e.Error()

			} else {
				r.tunnelStats.ClientConnErr = e.Error()

			}
		}
	}

	return
}
