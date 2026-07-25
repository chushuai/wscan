// Implementation of RFC 6143 §7.2 Security Types.

package vnc

import (
	"crypto/des"
)

const (
	secTypeInvalid  = uint8(0)
	secTypeNone     = uint8(1)
	secTypeVNCAuth  = uint8(2)
	secTypeVeNCrypt = uint8(19)
)

// ClientAuth implements a method of authenticating with a remote server.
type ClientAuth interface {
	// SecurityType returns the byte identifier sent by the server to
	// identify this authentication scheme.
	SecurityType() uint8

	// Handshake is called when the authentication handshake should be
	// performed, as part of the general RFB handshake. (see 7.2.1)
	Handshake(*ClientConn) error
}

// ClientAuthNone is the "none" authentication. See 7.2.1.
type ClientAuthNone struct{}

func (*ClientAuthNone) SecurityType() uint8 {
	return secTypeNone
}

func (*ClientAuthNone) Handshake(conn *ClientConn) error {
	return nil
}

// ClientAuthVNC is the standard password authentication. See 7.2.2.
type ClientAuthVNC struct {
	Password string
}

type vncAuthChallenge [16]byte

func (*ClientAuthVNC) SecurityType() uint8 {
	return secTypeVNCAuth
}

func (auth *ClientAuthVNC) Handshake(conn *ClientConn) error {

	// if auth.Password == "" {
	// 	return NewVNCError("Security Handshake failed; no password provided for VNCAuth.")
	// }

	// // Read challenge block
	// var challenge vncAuthChallenge
	// if err := conn.receive(&challenge); err != nil {
	// 	return err
	// }

	// auth.encode(&challenge)

	// // Send the encrypted challenge back to server
	// if err := conn.send(challenge); err != nil {
	// 	return err
	// }

	randomValue := make([]uint8, 16)
	if err := conn.receive(&randomValue); err != nil {
		return err
	}
	// if err := binary.Read(c, binary.BigEndian, &randomValue); err != nil {
	// 	return err
	// }

	crypted, err := auth.encrypt(auth.Password, randomValue)
	if err != nil {
		return err
	}
	if err := conn.send(crypted); err != nil {
		// if err := binary.Write(c, binary.BigEndian, &crypted); err != nil {
		return err
	}

	return nil
}

func (auth *ClientAuthVNC) encode(ch *vncAuthChallenge) error {
	// Copy password string to 8 byte 0-padded slice
	key := make([]byte, 8)
	copy(key, auth.Password)

	// Each byte of the password needs to be reversed. This is a
	// non RFC-documented behaviour of VNC clients and servers
	for i := range key {
		key[i] = (key[i]&0x55)<<1 | (key[i]&0xAA)>>1 // Swap adjacent bits
		key[i] = (key[i]&0x33)<<2 | (key[i]&0xCC)>>2 // Swap adjacent pairs
		key[i] = (key[i]&0x0F)<<4 | (key[i]&0xF0)>>4 // Swap the 2 halves
	}

	// Encrypt challenge with key.
	cipher, err := des.NewCipher(key)
	if err != nil {
		return err
	}
	for i := 0; i < len(ch); i += cipher.BlockSize() {
		cipher.Encrypt(ch[i:i+cipher.BlockSize()], ch[i:i+cipher.BlockSize()])
	}

	return nil
}

func (p *ClientAuthVNC) reverseBits(b byte) byte {
	var reverse = [256]int{
		0, 128, 64, 192, 32, 160, 96, 224,
		16, 144, 80, 208, 48, 176, 112, 240,
		8, 136, 72, 200, 40, 168, 104, 232,
		24, 152, 88, 216, 56, 184, 120, 248,
		4, 132, 68, 196, 36, 164, 100, 228,
		20, 148, 84, 212, 52, 180, 116, 244,
		12, 140, 76, 204, 44, 172, 108, 236,
		28, 156, 92, 220, 60, 188, 124, 252,
		2, 130, 66, 194, 34, 162, 98, 226,
		18, 146, 82, 210, 50, 178, 114, 242,
		10, 138, 74, 202, 42, 170, 106, 234,
		26, 154, 90, 218, 58, 186, 122, 250,
		6, 134, 70, 198, 38, 166, 102, 230,
		22, 150, 86, 214, 54, 182, 118, 246,
		14, 142, 78, 206, 46, 174, 110, 238,
		30, 158, 94, 222, 62, 190, 126, 254,
		1, 129, 65, 193, 33, 161, 97, 225,
		17, 145, 81, 209, 49, 177, 113, 241,
		9, 137, 73, 201, 41, 169, 105, 233,
		25, 153, 89, 217, 57, 185, 121, 249,
		5, 133, 69, 197, 37, 165, 101, 229,
		21, 149, 85, 213, 53, 181, 117, 245,
		13, 141, 77, 205, 45, 173, 109, 237,
		29, 157, 93, 221, 61, 189, 125, 253,
		3, 131, 67, 195, 35, 163, 99, 227,
		19, 147, 83, 211, 51, 179, 115, 243,
		11, 139, 75, 203, 43, 171, 107, 235,
		27, 155, 91, 219, 59, 187, 123, 251,
		7, 135, 71, 199, 39, 167, 103, 231,
		23, 151, 87, 215, 55, 183, 119, 247,
		15, 143, 79, 207, 47, 175, 111, 239,
		31, 159, 95, 223, 63, 191, 127, 255,
	}

	return byte(reverse[int(b)])
}

func (p *ClientAuthVNC) encrypt(key string, bytes []byte) ([]byte, error) {
	keyBytes := []byte{0, 0, 0, 0, 0, 0, 0, 0}

	if len(key) > 8 {
		key = key[:8]
	}

	for i := 0; i < len(key); i++ {
		keyBytes[i] = p.reverseBits(key[i])
	}

	block, err := des.NewCipher(keyBytes)

	if err != nil {
		return nil, err
	}

	result1 := make([]byte, 8)
	block.Encrypt(result1, bytes)
	result2 := make([]byte, 8)
	block.Encrypt(result2, bytes[8:])

	crypted := append(result1, result2...)

	return crypted, nil
}
