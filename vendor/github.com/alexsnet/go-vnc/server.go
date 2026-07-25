/*
Implementation of RFC 6143 §7.6 Server-to-Client Messages.
https://tools.ietf.org/html/rfc6143#section-7.6
*/
package vnc

import (
	"fmt"
	"image"

	"github.com/alexsnet/go-vnc/encodings"
	"github.com/alexsnet/go-vnc/messages"
	"github.com/alexsnet/go-vnc/rfbflags"
)

// ServerMessage is the interface satisfied by server messages.
type ServerMessage interface {
	// The type of the message that is sent down on the wire.
	Type() messages.ServerMessage

	// Read reads the contents of the message from the reader. At the point
	// this is called, the message type has already been read from the reader.
	// This should return a new ServerMessage that is the appropriate type.
	Read(*ClientConn) (ServerMessage, error)
}

//-----------------------------------------------------------------------------
// A framebuffer update consists of a sequence of rectangles of pixel data that
// the client should put into its framebuffer.
//
// See RFC 6143 Section 7.6.1.
// https://tools.ietf.org/html/rfc6143#section-7.6.1

// FramebufferUpdate holds a FramebufferUpdate wire format message.
type FramebufferUpdate struct {
	NumRect uint16      // number-of-rectangles
	Rects   []Rectangle // rectangles
}

// Verify that interfaces are honored.
var _ ServerMessage = (*FramebufferUpdate)(nil)
var _ MarshalerUnmarshaler = (*FramebufferUpdate)(nil)

func newFramebufferUpdate(rects []Rectangle) *FramebufferUpdate {
	return &FramebufferUpdate{
		NumRect: uint16(len(rects)),
		Rects:   rects,
	}
}

// Type implements the ServerMessage interface.
func (m *FramebufferUpdate) Type() messages.ServerMessage { return messages.FramebufferUpdate }

// Read implements the ServerMessage interface.
func (m *FramebufferUpdate) Read(c *ClientConn) (ServerMessage, error) {
	// Build the map of supported encodings.
	// encs := make(map[int32]Encoding)
	// for _, e := range c.Encodings() {
	// 	encs[e.Type()] = e
	// }
	// encs[Raw] = &RawEncoding{} // Raw encoding support required.

	// Read packet.
	var pad [1]byte
	if err := c.receive(&pad); err != nil {
		return nil, err
	}

	var numRects uint16
	if err := c.receive(&numRects); err != nil {
		return nil, err
	}

	// Extract rectangles.
	rects := make([]Rectangle, numRects)
	for i := 0; i < int(numRects); i++ {
		rect := NewRectangle(c.Encodable)
		if err := rect.Read(c); err != nil {
			return nil, err
		}
		rects[i] = *rect
	}

	return newFramebufferUpdate(rects), nil
}

// Marshal implements the Marshaler interface.
func (m *FramebufferUpdate) Marshal() ([]byte, error) {
	buf := NewBuffer(nil)
	msg := struct {
		msg      messages.ServerMessage // message-type
		_        [1]byte                // padding
		numRects uint16                 // number-of-rectangles
	}{
		msg:      messages.FramebufferUpdate,
		numRects: m.NumRect,
	}
	if err := buf.Write(msg); err != nil {
		return nil, err
	}
	for _, rect := range m.Rects {
		bytes, err := rect.Marshal()
		if err != nil {
			return nil, err
		}
		buf.Write(bytes)
	}

	return buf.Bytes(), nil
}

// Unmarshal implements the Unmarshaler interface.
func (m *FramebufferUpdate) Unmarshal(_ []byte) error {
	return fmt.Errorf("Unmarshal() unimplemented")
}

// EncodableFunc describes the function for encoding a Rectangle.
type EncodableFunc func(enc encodings.Encoding) (Encoding, bool)

// Encodable returns the Encoding that can be used to encode a Rectangle, or
// false if the encoding isn't recognized.
func (c *ClientConn) Encodable(enc encodings.Encoding) (Encoding, bool) {
	for _, e := range c.encodings {
		if e.Type() == enc {
			return e, true
		}
	}
	return nil, false
}

// rectangleMessage holds a Rectangle wire format message.
type rectangleMessage struct {
	X, Y uint16             // x-, y-position
	W, H uint16             // width, height
	E    encodings.Encoding // encoding-type
}

// Rectangle represents a rectangle of pixel data.
type Rectangle struct {
	X, Y          uint16
	Width, Height uint16
	Enc           Encoding
	encFn         EncodableFunc
}

// Verify that interfaces are honored.
var _ fmt.Stringer = (*Rectangle)(nil)
var _ MarshalerUnmarshaler = (*Rectangle)(nil)

// NewRectangle returns a new Rectangle object.
func NewRectangle(fn EncodableFunc) *Rectangle {
	return &Rectangle{encFn: fn}
}

// Read a rectangle message from ClientConn c.
func (r *Rectangle) Read(c *ClientConn) error {
	var msg rectangleMessage
	if err := c.receive(&msg); err != nil {
		return err
	}
	r.X, r.Y, r.Width, r.Height = msg.X, msg.Y, msg.W, msg.H

	encImpl, ok := r.encFn(msg.E)
	if !ok {
		return fmt.Errorf("unsupported encoding type: %d", msg.E)
	}

	enc, err := encImpl.Read(c, r)
	if err != nil {
		return fmt.Errorf("error reading rectangle encoding: %s", err)
	}

	r.Enc = enc
	return nil
}

// Marshal implements the Marshaler interface.
func (r *Rectangle) Marshal() ([]byte, error) {
	buf := NewBuffer(nil)

	var msg rectangleMessage
	msg.X, msg.Y, msg.W, msg.H = r.X, r.Y, r.Width, r.Height
	msg.E = r.Enc.Type()
	if err := buf.Write(msg); err != nil {
		return nil, err
	}

	bytes, err := r.Enc.Marshal()
	if err != nil {
		return nil, err
	}
	if err := buf.Write(bytes); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Unmarshal implements the Unmarshaler interface.
func (r *Rectangle) Unmarshal(data []byte) error {
	buf := NewBuffer(data)

	var msg rectangleMessage
	if err := buf.Read(&msg); err != nil {
		return err
	}
	r.X, r.Y, r.Width, r.Height = msg.X, msg.Y, msg.W, msg.H

	switch msg.E {
	case encodings.Raw:
		r.Enc = &RawEncoding{}
	default:
		return fmt.Errorf("unable to unmarshal encoding %v", msg.E)
	}
	return nil
}

// String implements the fmt.Stringer interface.
func (r *Rectangle) String() string {
	return fmt.Sprintf("{ x: %d y: %d, w: %d, h: %d, enc: %v }", r.X, r.Y, r.Width, r.Height, r.Enc)
}

// Area returns the total area in pixels of the Rectangle.
func (r *Rectangle) Area() int { return int(r.Width) * int(r.Height) }

//-----------------------------------------------------------------------------
// SetColorMapEntries is sent by the server to set values into
// the color map. This message will automatically update the color map
// for the associated connection, but contains the color change data
// if the consumer wants to read it.
//
// See RFC 6143 Section 7.6.2
// https://tools.ietf.org/html/rfc6143#section-7.6.2

// SetColorMapEntries holds a SetColorMapEntries wire format message, sans
// message-type and padding.
type SetColorMapEntries struct {
	FirstColor uint16
	Colors     []Color
}

// Verify that interfaces are honored.
var _ ServerMessage = (*SetColorMapEntries)(nil)

// Type implements the ServerMessage interface.
func (*SetColorMapEntries) Type() messages.ServerMessage { return messages.SetColorMapEntries }

// Read implements the ServerMessage interface.
func (*SetColorMapEntries) Read(c *ClientConn) (ServerMessage, error) {
	// Read off the padding
	var padding [1]byte
	if err := c.receive(&padding); err != nil {
		return nil, err
	}

	var result SetColorMapEntries
	if err := c.receive(&result.FirstColor); err != nil {
		return nil, err
	}

	var numColors uint16
	if err := c.receive(&numColors); err != nil {
		return nil, err
	}

	result.Colors = make([]Color, numColors)
	for i := uint16(0); i < numColors; i++ {
		color := &result.Colors[i]
		if err := c.receive(&color); err != nil {
			return nil, err
		}

		// Update the connection's color map
		c.colorMap[result.FirstColor+i] = *color
	}

	return &result, nil
}

// Color represents a single color in a color map.
type Color struct {
	pf      *PixelFormat
	cm      *ColorMap
	cmIndex uint32 // Only valid if pf.TrueColor is false.
	R, G, B uint16
}

// Verify that interfaces are honored.
var _ MarshalerUnmarshaler = (*Color)(nil)

// ColorMap represents a translation map of colors.
type ColorMap [256]Color

// NewColor returns a new Color object.
func NewColor(pf *PixelFormat, cm *ColorMap) *Color {
	return &Color{
		pf: pf,
		cm: cm,
	}
}

// Marshal implements the Marshaler interface.
func (c *Color) Marshal() ([]byte, error) {
	order := c.pf.order()
	pixel := c.cmIndex
	if rfbflags.IsTrueColor(c.pf.TrueColor) {
		pixel = uint32(c.R) << c.pf.RedShift
		pixel |= uint32(c.G) << c.pf.GreenShift
		pixel |= uint32(c.B) << c.pf.BlueShift
	}

	var bytes []byte
	switch c.pf.BPP {
	case 8:
		bytes = make([]byte, 1)
		bytes[0] = byte(pixel)
	case 16:
		bytes = make([]byte, 2)
		order.PutUint16(bytes, uint16(pixel))
	case 32:
		bytes = make([]byte, 4)
		order.PutUint32(bytes, pixel)
	}

	return bytes, nil
}

// Unmarshal implements the Unmarshaler interface.
func (c *Color) Unmarshal(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	order := c.pf.order()

	var pixel uint32
	switch c.pf.BPP {
	case 8:
		pixel = uint32(data[0])
	case 16:
		pixel = uint32(order.Uint16(data))
	case 32:
		pixel = order.Uint32(data)
	}

	if rfbflags.IsTrueColor(c.pf.TrueColor) {
		c.R = uint16((pixel >> c.pf.RedShift) & uint32(c.pf.RedMax))
		c.G = uint16((pixel >> c.pf.GreenShift) & uint32(c.pf.GreenMax))
		c.B = uint16((pixel >> c.pf.BlueShift) & uint32(c.pf.BlueMax))
	} else {
		*c = c.cm[pixel]
		c.cmIndex = pixel
	}

	return nil
}

func colorsToImage(x, y, width, height uint16, colors []Color) *image.RGBA64 {
	rect := image.Rect(int(x), int(y), int(x+width), int(y+height))
	rgba := image.NewRGBA64(rect)
	a := uint16(1)
	for i, color := range colors {
		rgba.Pix[4*i+0] = uint8(color.R >> 8)
		rgba.Pix[4*i+1] = uint8(color.R)
		rgba.Pix[4*i+2] = uint8(color.G >> 8)
		rgba.Pix[4*i+3] = uint8(color.G)
		rgba.Pix[4*i+4] = uint8(color.B >> 8)
		rgba.Pix[4*i+5] = uint8(color.B)
		rgba.Pix[4*i+6] = uint8(a >> 8)
		rgba.Pix[4*i+7] = uint8(a)
	}
	return rgba
}

//-----------------------------------------------------------------------------
// Bell signals that an audible bell should be made on the client.
//
// See RFC 6143 Section 7.6.3
// https://tools.ietf.org/html/rfc6143#section-7.6.3

// Bell represents the wire format message, sans message-type.
type Bell struct{}

// Verify that interfaces are honored.
var _ ServerMessage = (*Bell)(nil)

// Type implements the ServerMessage interface.
func (*Bell) Type() messages.ServerMessage { return messages.Bell }

// Read implements the ServerMessage interface.
func (*Bell) Read(c *ClientConn) (ServerMessage, error) {
	return &Bell{}, nil
}

//-----------------------------------------------------------------------------
// ServerCutText indicates the server has new text in the cut buffer.
//
// See RFC 6143 Section 7.6.4
// https://tools.ietf.org/html/rfc6143#section-7.6.4

// ServerCutText represents the wire format message, sans message-type and
// padding.
type ServerCutText struct {
	Text string
}

// Verify that interfaces are honored.
var _ ServerMessage = (*ServerCutText)(nil)

// Type implements the ServerMessage interface.
func (*ServerCutText) Type() messages.ServerMessage { return messages.ServerCutText }

// Read implements the ServerMessage interface.
func (*ServerCutText) Read(c *ClientConn) (ServerMessage, error) {
	// Read off the padding
	var padding [1]byte
	if err := c.receive(&padding); err != nil {
		return nil, err
	}

	var textLength uint32
	if err := c.receive(&textLength); err != nil {
		return nil, err
	}

	textBytes := make([]uint8, textLength)
	if err := c.receive(&textBytes); err != nil {
		return nil, err
	}

	return &ServerCutText{string(textBytes)}, nil
}
