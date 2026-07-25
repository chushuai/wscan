package rsync

import (
	"compress/flate"
	"io"
)

/*
	rsync uses zlib to do compression, the windowsBits is -15: raw data
*/

//nolint:revive,stylecheck
const (
	END_FLAG      = 0
	TOKEN_LONG    = 0x20
	TOKENRUN_LONG = 0x21
	DEFLATED_DATA = 0x40
	TOKEN_REL     = 0x80
	TOKENRUN_REL  = 0xc0
)

// RFC 1951: https://tools.ietf.org/html/rfc1951
type FlatedtokenReader struct {
	In           Conn
	Flatedwraper *flatedWraper
	Decompressor io.ReadCloser
	Savedflag    byte
	Flag         byte
	Remains      uint32
}

func NewflatedtokenReader(reader Conn) *FlatedtokenReader {
	w := &flatedWraper{
		raw: &reader,
		end: [4]byte{0, 0, 0xff, 0xff},
	}
	return &FlatedtokenReader{
		In:           reader,
		Flatedwraper: w,
		Decompressor: flate.NewReader(w),
		Savedflag:    0,
		Flag:         0,
		Remains:      0,
	}
}

// Update flag & len of remain data
func (f *FlatedtokenReader) ReadFlag() error {
	if f.Savedflag != 0 {
		f.Flag = f.Savedflag & 0xff
		f.Savedflag = 0
	} else {
		var err error
		if f.Flag, err = f.In.ReadByte(); err != nil {
			return err
		}
	}
	if (f.Flag & 0xc0) == DEFLATED_DATA {
		l, err := f.In.ReadByte()
		if err != nil {
			return err
		}
		f.Remains = uint32(f.Flag&0x3f)<<8 + uint32(l)
	}
	return nil
}

func (f *FlatedtokenReader) Read(p []byte) (n int, err error) {
	n, err = f.Decompressor.Read(p)
	f.Remains -= uint32(n)
	return
}

func (f *FlatedtokenReader) Close() error {
	return f.Decompressor.Close()
}

// Hack only: rsync need to append 4 bytes(0, 0, ff, ff) at the end.
type flatedWraper struct {
	raw io.Reader
	end [4]byte
}

func (f *flatedWraper) Read(p []byte) (n int, err error) {
	// Just append 4 bytes to the end of stream
	return f.raw.Read(p)
}
