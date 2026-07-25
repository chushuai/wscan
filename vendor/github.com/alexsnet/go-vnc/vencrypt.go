package vnc

import (
	"crypto/tls"
	"fmt"
)

type ClientAuthVeNCryptAuth struct{}

func (auth *ClientAuthVeNCryptAuth) SecurityType() uint8 {
	return secTypeVeNCrypt
}

func (auth *ClientAuthVeNCryptAuth) Handshake(c *ClientConn) error {
	// Version matching
	vencVersion := [2]uint8{}
	c.receive(&vencVersion)
	c.send([2]uint8{0, 2})

	// Is server accept choosen version?
	var isAccepted uint8
	c.receive(&isAccepted)
	if isAccepted != 0 {
		return fmt.Errorf("Server does not accept selected version")
	}

	var subtypesCnt uint8
	c.receive(&subtypesCnt)
	if subtypesCnt == 0 {
		return fmt.Errorf("Server sends 0 as SubTypes count")
	}

	switch vencVersion[1] {
	case 1:
		return fmt.Errorf("Client does not support 0.1 version of VeNCrypt")
	case 2:

		/*
			The sub-types are as follows:
			0: Failure
			256: Plain
			257: TLSNone
			258: TLSVnc
			259: TLSPlain
			260: X509None
			261: X509Vnc
			262: X509Plain
		*/

		subauthTypes := make([]int32, subtypesCnt)
		c.receiveN(&subauthTypes, int(subtypesCnt))
		if c.log != nil {
			c.log.Printf(" vencAccSubAuthTypes  %v", subauthTypes)
		}

		for _, x := range subauthTypes {
			if x == 261 {
				c.send(uint32(x))
				break
			}
		}
	}

	// Check for acceptance
	isAccepted = 255
	c.receive(&isAccepted)
	if isAccepted != 1 {
		return fmt.Errorf("Server does not accept")
	}

	// Making TLS Connection and switching original raw tcp to TLS covered
	tconn := tls.Client(c.Conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err := tconn.Handshake(); err != nil {
		panic(err)
	}
	c.Conn = tconn

	var cauth ClientAuth
	for _, a := range c.config.Auth {
		if a.SecurityType() == uint8(2) {
			cauth = a
		}
	}

	c.config.secType = cauth.SecurityType()
	if err := cauth.Handshake(c); err != nil {
		return err
	}

	return nil
}
