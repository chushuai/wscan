/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"time"
	"wscan/core/utils/log"
)

type IPRange struct {
	cidrList []*net.IPNet
	ipStubs  [][2]int64
	strList  []string
}

//*utils.IPRange
func (*IPRange) StrInRange(string) bool {
	return false
}

// timeoutError type
type timeoutError struct {
	error
	timeout bool
}

// Error method
func (e *timeoutError) Error() string {
	return e.error.Error()
}

// Timeout method
func (e *timeoutError) Timeout() bool {
	return e.timeout
}

// Temporary method
func (e *timeoutError) Temporary() bool {
	return true
}

type TimeoutConn struct {
	net.Conn
	timeout           int64
	allowPartialWrite bool
}

// 1. Close method
func (c *TimeoutConn) Close() error {
	return c.Conn.Close()
}

// 2. LocalAddr method
func (c *TimeoutConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// 3. RemoteAddr method
func (c *TimeoutConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

// 4. SetDeadline method
func (c *TimeoutConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

// 5. SetReadDeadline method
func (c *TimeoutConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

// 6. SetWriteDeadline method
func (c *TimeoutConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// 7. SetTLSHandshakeTimeout method
func (c *TimeoutConn) SetTLSHandshakeTimeout(timeout time.Duration) {
	c.Conn = tls.Client(c.Conn, &tls.Config{
		InsecureSkipVerify: true,
	})
}

// 8. SetNoReadTimeout method
func (c *TimeoutConn) SetNoReadTimeout() {
	c.timeout = 0
}

// 9. print method
func (c *TimeoutConn) print() {
	log.Printf("TimeoutConn: LocalAddr=%v RemoteAddr=%v timeout=%v allowPartialWrite=%v", c.LocalAddr(), c.RemoteAddr(), c.timeout, c.allowPartialWrite)
}

// 10. IsTimeout method
func (c *TimeoutConn) IsTimeout(err error) bool {
	if err, ok := err.(net.Error); ok && err.Timeout() {
		return true
	}
	return false
}

// 11. ReadUntil method
func (c *TimeoutConn) ReadUntil(delim byte) ([]byte, error) {
	var buffer bytes.Buffer
	for {
		b := make([]byte, 1)
		_, err := c.ReadWithTimeout(b)
		if err != nil {
			return nil, err
		}
		buffer.Write(b)
		if b[0] == delim {
			break
		}
	}
	return buffer.Bytes(), nil
}

// 12. ReadAllWithTimeout method
func (c *TimeoutConn) ReadAllWithTimeout() ([]byte, error) {
	var buffer bytes.Buffer
	for {
		b := make([]byte, 1024)
		n, err := c.ReadWithTimeout(b)
		if err != nil {
			if c.IsTimeout(err) {
				return nil, &timeoutError{err, true}
			}
			if err == io.EOF {
				return buffer.Bytes(), nil
			}
			return nil, err
		}
		buffer.Write(b[:n])
	}
}

// ReadWithTimeout method
func (c *TimeoutConn) ReadWithTimeout(b []byte) (int, error) {
	if c.timeout > 0 {
		c.Conn.SetReadDeadline(time.Now().Add(time.Duration(c.timeout) * time.Second))
	}
	n, err := c.Conn.Read(b)
	if c.timeout > 0 {
		if c.IsTimeout(err) {
			return n, &timeoutError{err, true}
		}
		c.Conn.SetReadDeadline(time.Time{})
	}
	return n, err
}
