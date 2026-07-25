// Common things that aren't part of the RFB protocol.

package vnc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// VNCError implements error interface.
type VNCError struct {
	desc string
}

// NewVNCError returns a custom VNCError error.
func NewVNCError(desc string) error {
	return &VNCError{desc}
}

// Error returns an VNCError as a string.
func (e VNCError) Error() string {
	return e.desc
}

func Errorf(format string, a ...interface{}) error {
	return &VNCError{
		desc: fmt.Sprintf(format, a...),
	}
}

var settleDuration = 25 * time.Millisecond

// Settle returns the UI settle duration.
func Settle() time.Duration {
	return settleDuration
}

// SetSettle changes the UI settle duration.
func SetSettle(s time.Duration) {
	settleDuration = s
}

// settleUI allows the UI to "settle" before the next UI change is made.
func settleUI() {
	time.Sleep(settleDuration)
}

type Buffer struct {
	buf *bytes.Buffer // byte stream
}

func NewBuffer(b []byte) *Buffer {
	return &Buffer{buf: bytes.NewBuffer(b)}
}

func (b *Buffer) Bytes() []byte {
	return b.buf.Bytes()
}

func (b *Buffer) Read(data interface{}) error {
	return binary.Read(b.buf, binary.BigEndian, data)
}

func (b *Buffer) Write(data interface{}) error {
	return binary.Write(b.buf, binary.BigEndian, data)
}

func (b *Buffer) WriteByte(c byte) error {
	return b.buf.WriteByte(c)
}

// Marshaler is the interface satisfied for marshaling messages.
type Marshaler interface {
	// Marshal returns the wire encoding of a message.
	Marshal() ([]byte, error)
}

// Unarshaler is the interface satisfied for unmarshaling messages.
type Unmarshaler interface {
	// Unmarshal parses a wire format message into a message.
	Unmarshal(data []byte) error
}

// MarshalerUnmarshaler satisfies both the Marshaler and Unmarshaler interfaces.
type MarshalerUnmarshaler interface {
	Marshaler
	Unmarshaler
}
