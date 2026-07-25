/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"bufio"
	"net"
)

type PeekConn struct {
	net.Conn
	r       *bufio.Reader
	reverse *Reverse
}

func (c *PeekConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (c *PeekConn) Peek(n int) ([]byte, error) {
	return c.r.Peek(n)
}

func NewPeekConn(c net.Conn) *PeekConn {
	return &PeekConn{Conn: c,
		r: bufio.NewReader(c),
	}
}

type Listener struct {
	net.Listener
	reverse      *Reverse
	peekConnChan chan *PeekConn
}

func NewListener(l net.Listener, reverse *Reverse) *Listener {
	ll := &Listener{
		Listener:     l,
		reverse:      reverse,
		peekConnChan: make(chan *PeekConn),
	}

	go func(ln *Listener) {
		for {
			conn, err := ln.Listener.Accept()
			if err != nil {
				continue
			}
			go func(c net.Conn) {
				peekableConn := NewPeekConn(c)
				raw, err := peekableConn.Peek(3)
				if err != nil {
					return
				}
				switch raw[0] {
				case 0x30:
					ln.reverse.reverseLdapServer.Handle(peekableConn)
				case 'J': // 4a524d49 (JRMI)
					ln.reverse.reverseRMIServer.Handle(peekableConn)
				default:
					// 其它如http/https服务
					ln.peekConnChan <- peekableConn
				}
			}(conn)
		}
	}(ll)

	return ll
}
func (ln *Listener) Accept() (net.Conn, error) {
	select {
	case conn := <-ln.peekConnChan:
		return conn, nil
	}
	return nil, nil
}
