/*
Package messages provides constants for the client and server messages.
*/
package messages

//-----------------------------------------------------------------------------
// Client messages
//
// Client-to-Server: https://tools.ietf.org/html/rfc6143#section-7.5

// ClientMessage represents a Client-to-Server RFB message type.
type ClientMessage uint8

//go:generate stringer -type=ClientMessage

// Client-to-Server message types.
const (
	SetPixelFormat ClientMessage = iota
	_
	SetEncodings
	FramebufferUpdateRequest
	KeyEvent
	PointerEvent
	ClientCutText
)

//-----------------------------------------------------------------------------
// Server messages
//
// Server-to-Client: https://tools.ietf.org/html/rfc6143#section-7.6

// ServerMessage represents a Server-to-Client RFB message type.
type ServerMessage uint8

//go:generate stringer -type=ServerMessage

// Server-to-Client message types.
const (
	FramebufferUpdate ServerMessage = iota
	SetColorMapEntries
	Bell
	ServerCutText
)
