package rsync

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
)

//Multiplexing
//Most rsync transmissions are wrapped in a multiplexing envelope protocol.  It is
//composed as follows:
//
//1.   envelope header (4 bytes)
//2.   envelope payload (arbitrary length)
//
//The first byte of the envelope header consists of a tag.  If the tag is 7, the pay‐
//load is normal data.  Otherwise, the payload is out-of-band server messages.  If the
//tag is 1, it is an error on the sender's part and must trigger an exit.  This limits
//message payloads to 24 bit integer size, 0x00ffffff.
//
//The only data not using this envelope are the initial handshake between client and
//server

type MuxReader struct {
	In     io.ReadCloser
	Remain uint32 // Default value: 0
	Header []byte // Size: 4 bytes
	Logger *slog.Logger
}

func NewMuxReader(reader io.ReadCloser, logger *slog.Logger) *MuxReader {
	return &MuxReader{
		In:     reader,
		Remain: 0,
		Header: make([]byte, 4),
		Logger: logger,
	}
}

func (r *MuxReader) Read(p []byte) (n int, err error) {
	if r.Remain == 0 {
		err := r.readHeader()
		if err != nil {
			return 0, err
		}
	}
	rlen := uint32(len(p))
	if rlen > r.Remain { // Min(len(p), remain)
		rlen = r.Remain
	}
	n, err = r.In.Read(p[:rlen])
	r.Remain = r.Remain - uint32(n)
	return
}

func (r *MuxReader) readHeader() error {
	for {
		// Read header
		if _, err := io.ReadFull(r.In, r.Header); err != nil {
			return err
		}
		tag := r.Header[3]                                        // Little Endian
		size := (binary.LittleEndian.Uint32(r.Header) & 0xffffff) // TODO: zero?

		if tag == (MUX_BASE + MSG_DATA) { // MUX_BASE + MSG_DATA
			r.Remain = size
			return nil
		} else { //nolint:revive // out-of-band data
			// otag := tag - 7
			msg := make([]byte, size)
			if _, err := io.ReadFull(r.In, msg); err != nil {
				return err
			}
			return errors.New(string(msg))
		}
	}
}

func (r *MuxReader) Close() error {
	return r.In.Close()
}
