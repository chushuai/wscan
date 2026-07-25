// VNC client implementation.

package vnc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"reflect"

	"context"

	"github.com/alexsnet/go-vnc/go/metrics"
	"github.com/alexsnet/go-vnc/messages"
)

type ReadProxy struct {
	or io.Reader
}

func (rp *ReadProxy) Read(p []byte) (n int, err error) {
	n, err = rp.or.Read(p)
	fmt.Printf("Read: %v\n", p)
	return
}

// Connect negotiates a connection to a VNC server.
func Connect(ctx context.Context, c net.Conn, cfg *ClientConfig) (*ClientConn, error) {
	conn := NewClientConn(c, cfg)

	if err := conn.processContext(ctx); err != nil {
		log.Fatalf("invalid context; %s", err)
	}

	if err := conn.protocolVersionHandshake(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.securityHandshake(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.securityResultHandshake(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.clientInit(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := conn.serverInit(); err != nil {
		conn.Close()
		return nil, err
	}

	// Send client-to-server messages.
	encs := conn.encodings
	if err := conn.SetEncodings(encs); err != nil {
		conn.Close()
		return nil, Errorf("failure calling SetEncodings; %s", err)
	}

	pf := conn.pixelFormat
	if err := conn.SetPixelFormat(pf); err != nil {
		conn.Close()
		return nil, Errorf("failure calling SetPixelFormat; %s", err)
	}

	return conn, nil
}

// A ClientConfig structure is used to configure a ClientConn. After
// one has been passed to initialize a connection, it must not be modified.
type ClientConfig struct {
	secType uint8 // The negotiated security type.

	// A slice of ClientAuth methods. Only the first instance that is
	// suitable by the server will be used to authenticate.
	Auth []ClientAuth

	// Password for servers that require authentication.
	Password string

	// Logger
	Logger *log.Logger

	// Exclusive determines whether the connection is shared with other
	// clients. If true, then all other clients connected will be
	// disconnected when a connection is established to the VNC server.
	Exclusive bool

	// The channel that all messages received from the server will be
	// sent on. If the channel blocks, then the goroutine reading data
	// from the VNC server may block indefinitely. It is up to the user
	// of the library to ensure that this channel is properly read.
	// If this is not set, then all messages will be discarded.
	ServerMessageCh chan ServerMessage

	// A slice of supported messages that can be read from the server.
	// This only needs to contain NEW server messages, and doesn't
	// need to explicitly contain the RFC-required messages.
	ServerMessages []ServerMessage
}

// NewClientConfig returns a populated ClientConfig.
func NewClientConfig(p string) *ClientConfig {
	return &ClientConfig{
		Auth: []ClientAuth{
			&ClientAuthNone{},
			&ClientAuthVNC{p},
			&ClientAuthVeNCryptAuth{},
		},
		Password: p,
		ServerMessages: []ServerMessage{
			&FramebufferUpdate{},
			&SetColorMapEntries{},
			&Bell{},
			&ServerCutText{},
		},
	}
}

// The ClientConn type holds client connection information.
type ClientConn struct {
	Conn            net.Conn
	config          *ClientConfig
	protocolVersion string

	connTerminated bool

	log *log.Logger

	// If the pixel format uses a color map, then this is the color
	// map that is used. This should not be modified directly, since
	// the data comes from the server.
	// Definition in §5 - Representation of Pixel Data.
	colorMap ColorMap

	// Name associated with the desktop, sent from the server.
	desktopName string

	// Encodings supported by the client. This should not be modified
	// directly. Instead, SetEncodings() should be used.
	encodings Encodings

	// Height of the frame buffer in pixels, sent from the server.
	fbHeight uint16

	// Width of the frame buffer in pixels, sent from the server.
	fbWidth uint16

	// The pixel format associated with the connection. This shouldn't
	// be modified. If you wish to set a new pixel format, use the
	// SetPixelFormat method.
	pixelFormat PixelFormat

	// Security types, supported by the server
	securityTypes []uint8

	// Track metrics on system performance.
	metrics map[string]metrics.Metric
}

func NewClientConn(c net.Conn, cfg *ClientConfig) *ClientConn {
	return &ClientConn{
		Conn:           c,
		connTerminated: false,
		config:         cfg,
		log:            cfg.Logger,
		encodings:      Encodings{&RawEncoding{}},
		pixelFormat:    PixelFormat32bit,
		metrics: map[string]metrics.Metric{
			"bytes-received": &metrics.Gauge{},
			"bytes-sent":     &metrics.Gauge{},
		},
	}
}

// Close a connection to a VNC server.
func (c *ClientConn) Close() error {
	if c.log != nil {
		c.log.Println("VNC Client connection closed.")
	}
	c.connTerminated = true
	return c.Conn.Close()
}

// DesktopName returns the server provided desktop name.
func (c *ClientConn) DesktopName() string {
	return c.desktopName
}

// setDesktopName stores the server provided desktop name.
func (c *ClientConn) setDesktopName(name string) {
	if c.log != nil {
		c.log.Printf("desktopName: %s\n", name)
	}
	c.desktopName = name
}

// Encodings returns the server provided encodings.
func (c *ClientConn) Encodings() Encodings {
	return c.encodings
}

// FramebufferHeight returns the server provided framebuffer height.
func (c *ClientConn) FramebufferHeight() uint16 {
	return c.fbHeight
}

// setFramebufferHeight stores the server provided framebuffer height.
func (c *ClientConn) setFramebufferHeight(height uint16) {
	if c.log != nil {
		c.log.Printf("height: %d", height)
	}
	c.fbHeight = height
}

// FramebufferWidth returns the server provided framebuffer width.
func (c *ClientConn) FramebufferWidth() uint16 {
	return c.fbWidth
}

// setFramebufferWidth stores the server provided framebuffer width.
func (c *ClientConn) setFramebufferWidth(width uint16) {
	if c.log != nil {
		c.log.Printf("width: %d", width)
	}
	c.fbWidth = width
}

// ListenAndHandle listens to a VNC server and handles server messages.
func (c *ClientConn) ListenAndHandle() error {
	if c.config.ServerMessages == nil {
		return NewVNCError("Client config error: ServerMessages undefined")
	}
	serverMessages := make(map[messages.ServerMessage]ServerMessage)
	for _, m := range c.config.ServerMessages {
		serverMessages[m.Type()] = m
	}

	for {
		var messageType messages.ServerMessage
		if err := c.receive(&messageType); err != nil {
			if !c.connTerminated {
				log.Print("error: reading from server")
			}
			break
		}
		if c.log != nil {
			c.log.Printf("message-type: %s", messageType)
		}

		msg, ok := serverMessages[messageType]
		if !ok {
			// Unsupported message type! Bad!
			log.Printf("error unsupported message-type: %v", messageType)
			break
		}

		parsedMsg, err := msg.Read(c)
		if err != nil {
			log.Printf("error parsing message; %v", err)
			break
		}

		if c.config.ServerMessageCh == nil {
			log.Print("ignoring message; no server message channel")
			continue
		}

		c.config.ServerMessageCh <- parsedMsg
	}

	log.Print("ListenAndHandle finished")
	return nil
}

// receive a packet from the network.
func (c *ClientConn) receive(data interface{}) error {
	if err := binary.Read(c.Conn, binary.BigEndian, data); err != nil {
		return err
	}
	c.metrics["bytes-received"].Adjust(int64(binary.Size(data)))
	return nil
}

// receiveN receives N packets from the network.
func (c *ClientConn) receiveN(data interface{}, n int) error {
	if n == 0 {
		return nil
	}

	switch data.(type) {
	case *[]uint8:
		var v uint8
		for i := 0; i < n; i++ {
			if err := binary.Read(c.Conn, binary.BigEndian, &v); err != nil {
				return err
			}
			slice := data.(*[]uint8)
			*slice = append(*slice, v)
		}
	case *[]int32:
		var v int32
		for i := 0; i < n; i++ {
			if err := binary.Read(c.Conn, binary.BigEndian, &v); err != nil {
				return err
			}
			slice := data.(*[]int32)
			*slice = append(*slice, v)
		}
	case *bytes.Buffer:
		var v byte
		for i := 0; i < n; i++ {
			if err := binary.Read(c.Conn, binary.BigEndian, &v); err != nil {
				return err
			}
			buf := data.(*bytes.Buffer)
			buf.WriteByte(v)
		}
	default:
		return NewVNCError(fmt.Sprintf("unrecognized data type %v", reflect.TypeOf(data)))
	}
	c.metrics["bytes-received"].Adjust(int64(binary.Size(data)))
	return nil
}

// send a packet to the network.
func (c *ClientConn) send(data interface{}) error {
	if err := binary.Write(c.Conn, binary.BigEndian, data); err != nil {
		return err
	}

	c.metrics["bytes-sent"].Adjust(int64(binary.Size(data)))
	return nil
}

// sendN sends N packets to the network.
// func (c *ClientConn) sendN(data interface{}, n int) error {
// 	var buf bytes.Buffer
// 	switch data := data.(type) {
// 	case []uint8:
// 		for _, d := range data {
// 			if err := binary.Write(&buf, binary.BigEndian, &d); err != nil {
// 				return err
// 			}
// 		}
// 	case []int32:
// 		for _, d := range data {
// 			if err := binary.Write(&buf, binary.BigEndian, &d); err != nil {
// 				return err
// 			}
// 		}
// 	default:
// 		return NewVNCError(fmt.Sprintf("unable to send data; unrecognized data type %v", reflect.TypeOf(data)))
// 	}
// 	if err := binary.Write(c.c, binary.BigEndian, buf.Bytes()); err != nil {
// 		return err
// 	}
// 	c.metrics["bytes-sent"].Adjust(int64(binary.Size(data)))
// 	return nil
// }

func (c *ClientConn) processContext(ctx context.Context) error {
	if mpv := ctx.Value("vnc_max_proto_version"); mpv != nil && mpv != "" {
		log.Printf("vnc_max_proto_version: %v", mpv)
		vers := []string{"3.3", "3.8"}
		valid := false
		for _, v := range vers {
			if mpv == v {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("Invalid max protocol version %v; supported versions are %v", mpv, vers)
		}
	}

	return nil
}

func (c *ClientConn) DebugMetrics() {
	log.Println("Metrics:")
	for name, metric := range c.metrics {
		log.Printf("  %v: %v", name, metric.Value())
	}
}
