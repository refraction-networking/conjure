package lib

import (
	"errors"
	"io"
	"sync"
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
	m           *sync.Mutex
	d           direction
	nonZeroHook func()
}

func newRater(r io.Reader, ts *tunnelStats, s *Stats, dir direction) *rateWrapper {
	var m sync.Mutex
	rd := &rateWrapper{
		r:           r,
		tunnelStats: ts,
		sharedStats: s,
		m:           &m,
	}
	return rd
}

func (r *rateWrapper) Read(c []byte) (n int, err error) {
	r.m.Lock()
	defer r.m.Unlock()

	n, err = r.r.Read(c)

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

	if r != nil {
		r.nonZeroHook()
	}

	return
}

var errNotExist = errors.New("does not exist")

type errWrapper struct {
	r io.Reader
	w io.Writer

	tunnelStats *tunnelStats
	m           *sync.Mutex
	d           direction
}

func newWriteErrWrapper(r io.Reader, ts *tunnelStats, dir direction) *errWrapper {
	var m sync.Mutex
	return &errWrapper{
		r:           r,
		tunnelStats: ts,
		m:           &m,
	}
}

func newReadErrWrapper(w io.Writer, ts *tunnelStats, dir direction) *errWrapper {
	var m sync.Mutex
	return &errWrapper{
		w:           w,
		tunnelStats: ts,
		m:           &m,
	}
}

func (r *errWrapper) Read(c []byte) (n int, err error) {
	if r.r == nil {
		return 0, errNotExist
	}

	n, err = r.r.Read(c)

	if err != nil {
		if e := generalizeErr(err); e != nil {
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
	if r.w == nil {
		return 0, errNotExist
	}

	n, err = r.w.Write(c)

	if err != nil {
		if e := generalizeErr(err); e != nil {
			if r.d == up {
				r.tunnelStats.CovertConnErr = e.Error()

			} else {
				r.tunnelStats.ClientConnErr = e.Error()

			}
		}
	}

	return
}
