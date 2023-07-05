package lib

/*
// // Commenting out these utils as they are unused - They are associated with
// // the ThreeWayProxy transport that was never completed and has itself been
// // removed to a comment.


// bufferedReaderConn allows to combine *bufio.Reader(conn) and *conn into one
struct. // Implements net.Conn type bufferedReaderConn struct { net.Conn R
*bufio.Reader
}

func (bc *bufferedReaderConn) Read(b []byte) (n int, err error) { return
    bc.R.Read(b)
}

func (bc *bufferedReaderConn) Peek(n int) ([]byte, error) { return bc.R.Peek(n)
}

func (bc *bufferedReaderConn) CloseWrite() error { if closeWriter, ok :=
    bc.Conn.(interface { CloseWrite() error }); ok { return
    closeWriter.CloseWrite()
    }
    return errors.New("not a CloseWriter")

}

func (bc *bufferedReaderConn) CloseRead() error { if closeReader, ok :=
    bc.Conn.(interface { CloseRead() error }); ok { return
    closeReader.CloseRead()
    }
    return errors.New("not a CloseReader")

}

func makeBufferedReaderConn(c net.Conn, r *bufio.Reader) *bufferedReaderConn {
    return &bufferedReaderConn{ Conn: c, R:    r,
    }
}

*/
