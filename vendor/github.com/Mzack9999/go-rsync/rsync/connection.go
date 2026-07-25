package rsync

import (
	"bytes"
	"encoding/binary"
	"io"
)

type SendReceiver interface {
	Sync() error
	GetSyncPlan() (*SyncPlan, error)
	List() (FileList, error)
}

// io.ReadWriteCloser
// This struct has two main attributes, both of them can be used for a plain socket or an SSH
type Conn struct {
	Writer    io.WriteCloser // Write only
	Reader    io.ReadCloser  // Read only
	Bytespool []byte         // Anti memory-wasted, default size: 8 bytes
}

func (conn *Conn) Write(p []byte) (n int, err error) {
	return conn.Writer.Write(p)
}

func (conn *Conn) Read(p []byte) (n int, err error) {
	return conn.Reader.Read(p)
}

/* Encoding: little endian */
// size of: int: 4, long: 8, varint: 4 or 8
func (conn *Conn) ReadByte() (byte, error) {
	val := conn.Bytespool[:1]
	_, err := io.ReadFull(conn, val)
	if err != nil {
		return 0, err
	}
	return conn.Bytespool[0], nil
}

func (conn *Conn) ReadShort() (int16, error) {
	val := conn.Bytespool[:2]
	_, err := io.ReadFull(conn, val)
	if err != nil {
		return 0, err
	}
	return int16(binary.LittleEndian.Uint16(val)), nil
}

func (conn *Conn) ReadInt() (int32, error) {
	val := conn.Bytespool[:4]
	_, err := io.ReadFull(conn, val)
	if err != nil {
		return 0, err
	}
	return int32(binary.LittleEndian.Uint32(val)), nil
}

func (conn *Conn) ReadLong() (int64, error) {
	val := conn.Bytespool[:8]
	_, err := io.ReadFull(conn, val)
	if err != nil {
		return 0, err
	}
	return int64(binary.LittleEndian.Uint64(val)), nil
}

func (conn *Conn) ReadVarint() (int64, error) {
	sval, err := conn.ReadInt()
	if err != nil {
		return 0, err
	}
	if sval != -1 {
		return int64(sval), nil
	}
	return conn.ReadLong()
}

func (conn *Conn) WriteByte(data byte) error {
	return binary.Write(conn.Writer, binary.LittleEndian, data)
}

func (conn *Conn) WriteShort(data int16) error {
	return binary.Write(conn.Writer, binary.LittleEndian, data)
}

func (conn *Conn) WriteInt(data int32) error {
	return binary.Write(conn.Writer, binary.LittleEndian, data)
}

func (conn *Conn) WriteLong(data int64) error {
	return binary.Write(conn.Writer, binary.LittleEndian, data)
}

// TODO: If both writer and reader are based on a same Connection (socket, SSH), how to close them twice?
func (conn *Conn) Close() error {
	_ = conn.Writer.Close()
	_ = conn.Reader.Close()
	return nil
}

func readLine(conn *Conn) (string, error) {
	// Read until newline, which is what rsync daemon uses
	line := new(bytes.Buffer)
	for {
		c, err := conn.ReadByte()
		if err != nil {
			return "", err
		}

		if c == '\r' {
			continue // Skip carriage returns
		}

		if c == '\n' {
			break // End of line
		}

		err = line.WriteByte(c)
		if err != nil {
			return "", err
		}
	}

	// Return the line without the newline
	return line.String(), nil
}
