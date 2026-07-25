package gostruct

// Package binary_pack performs conversions between some Go values represented as byte slices.
// This can be used in handling binary data stored in files or from network connections,
// among other sources. It uses format slices of strings as compact descriptions of the layout
// of the C structs.
//
// 	Format characters
// 		? - bool, packed size 1 byte
//		> - big endian
//		< - little endian
// 		h, H - int, packed size 2 bytes (in future it will support pack/unpack of int8, uint8 values)
// 		i, I, l, L - int, packed size 4 bytes (in future it will support pack/unpack of int16, uint16, int32, uint32 values)
// 		q, Q - int, packed size 8 bytes (in future it will support pack/unpack of int64, uint64 values)
// 		f - float32, packed size 4 bytes
// 		d - float64, packed size 8 bytes
// 		Ns - string, packed size N bytes, N is a number of runes to pack/unpack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Endianess int

const (
	BIG_ENDIAN Endianess = iota
	LITTLE_ENDIAN
)

func (e Endianess) ByteOrder() binary.ByteOrder {
	if e == BIG_ENDIAN {
		return binary.BigEndian
	} else {
		return binary.LittleEndian
	}
}

// Return a byte slice containing the values of msg slice packed according to the given format.
// The items of msg slice must match the values required by the format exactly.
func Pack(format []string, msg []interface{}) ([]byte, error) {
	res := []byte{}

	endianess := LITTLE_ENDIAN
	var msgIdx int

	for _, f := range format {
		switch f {
		case "<":
			endianess = LITTLE_ENDIAN
		case ">", "!":
			endianess = BIG_ENDIAN
		case "b", "B":
			castedValue, ok := msg[msgIdx].(int)
			if !ok {
				return nil, errors.New("Type of passed value doesn't match to expected '" + f + "' (int, 2 bytes)")
			}
			res = append(res, intToBytes(castedValue, 1, endianess)...)
			msgIdx++
		case "?":
			castedValue, ok := msg[msgIdx].(bool)
			if !ok {
				return nil, errors.New("Type of passed value doesn't match to expected '" + f + "' (bool)")
			}
			res = append(res, boolToBytes(castedValue, endianess)...)
			msgIdx++
		case "h", "H":
			castedValue, ok := msg[msgIdx].(int)
			if !ok {
				return nil, errors.New("Type of passed value doesn't match to expected '" + f + "' (int, 2 bytes)")
			}
			res = append(res, intToBytes(castedValue, 2, endianess)...)
			msgIdx++
		case "i", "I", "l", "L":
			castedValue, ok := msg[msgIdx].(int)
			if !ok {
				return nil, errors.New("Type of passed value doesn't match to expected '" + f + "' (int, 4 bytes)")
			}
			res = append(res, intToBytes(castedValue, 4, endianess)...)
			msgIdx++
		case "q", "Q":
			castedValue, ok := msg[msgIdx].(int)
			if !ok {
				return nil, errors.New("Type of passed value doesn't match to expected '" + f + "' (int, 8 bytes)")
			}
			res = append(res, intToBytes(castedValue, 8, endianess)...)
			msgIdx++
		case "f":
			castedValue, ok := msg[msgIdx].(float32)
			if !ok {
				return nil, errors.New("Type of passed value doesn't match to expected '" + f + "' (float32)")
			}
			res = append(res, float32ToBytes(castedValue, 4, endianess)...)
			msgIdx++
		case "d":
			castedValue, ok := msg[msgIdx].(float64)
			if !ok {
				return nil, errors.New("Type of passed value doesn't match to expected '" + f + "' (float64)")
			}
			res = append(res, float64ToBytes(castedValue, 8, endianess)...)
			msgIdx++
		default:
			if strings.Contains(f, "s") {
				castedValue, ok := msg[msgIdx].(string)
				if !ok {
					return nil, errors.New("Type of passed value doesn't match to expected '" + f + "' (string)")
				}
				n, _ := strconv.Atoi(strings.TrimRight(f, "s"))
				res = append(res, []byte(fmt.Sprintf("%s%s",
					castedValue, strings.Repeat("\x00", n-len(castedValue))))...)
			} else {
				return nil, errors.New("Unexpected format token: '" + f + "'")
			}
			msgIdx++
		}
	}

	return res, nil
}

// Unpack the byte slice (presumably packed by Pack(format, msg)) according to the given format.
// The result is a []interface{} slice even if it contains exactly one item.
// The byte slice must contain not less the amount of data required by the format
// (len(msg) must more or equal CalcSize(format)).
func UnPack(format []string, msg []byte) ([]interface{}, error) {
	expected_size, err := CalcSize(format)

	endianess := LITTLE_ENDIAN

	if err != nil {
		return nil, err
	}

	if expected_size > len(msg) {
		return nil, errors.New("expected size is bigger than actual size of message")
	}

	res := []interface{}{}

	for _, f := range format {
		switch f {
		case "<":
			endianess = LITTLE_ENDIAN
		case ">":
			endianess = BIG_ENDIAN
		case "?":
			res = append(res, bytesToBool(msg[:1], endianess))
			msg = msg[1:]
		case "b":
			res = append(res, bytesToInt(msg[:1], endianess))
			msg = msg[1:]
		case "B":
			res = append(res, bytesToUint(msg[:1]))
			msg = msg[1:]
		case "h", "H":
			res = append(res, bytesToInt(msg[:2], endianess))
			msg = msg[2:]
		case "i", "I", "l", "L":
			res = append(res, bytesToInt(msg[:4], endianess))
			msg = msg[4:]
		case "q", "Q":
			res = append(res, bytesToInt(msg[:8], endianess))
			msg = msg[8:]
		case "f":
			res = append(res, bytesToFloat32(msg[:4], endianess))
			msg = msg[4:]
		case "d":
			res = append(res, bytesToFloat64(msg[:8], endianess))
			msg = msg[8:]
		default:
			if strings.Contains(f, "s") {
				n, _ := strconv.Atoi(strings.TrimRight(f, "s"))
				res = append(res, string(msg[:n]))
				msg = msg[n:]
			} else {
				return nil, errors.New("Unexpected format token: '" + f + "'")
			}
		}
	}

	return res, nil
}

// Return the size of the struct (and hence of the byte slice) corresponding to the given format.
func CalcSize(format []string) (int, error) {
	var size int

	for _, f := range format {
		switch f {
		case "<", ">":
			// unused
		case "?":
			size = size + 1
		case "b", "B":
			size++
		case "h", "H":
			size = size + 2
		case "i", "I", "l", "L", "f":
			size = size + 4
		case "q", "Q", "d":
			size = size + 8
		default:
			if strings.Contains(f, "s") {
				n, _ := strconv.Atoi(strings.TrimRight(f, "s"))
				size = size + n
			} else {
				return 0, errors.New("Unexpected format token: '" + f + "'")
			}
		}
	}

	return size, nil
}

func boolToBytes(x bool, endianess Endianess) []byte {
	if x {
		return intToBytes(1, 1, endianess)
	}
	return intToBytes(0, 1, endianess)
}

func bytesToBool(b []byte, endianess Endianess) bool {
	return bytesToInt(b, endianess) > 0
}

func intToBytes(n int, size int, endianess Endianess) []byte {
	buf := bytes.NewBuffer([]byte{})

	switch size {
	case 1:
		_ = binary.Write(buf, endianess.ByteOrder(), int8(n))
	case 2:
		_ = binary.Write(buf, endianess.ByteOrder(), int16(n))
	case 4:
		_ = binary.Write(buf, endianess.ByteOrder(), int32(n))
	default:
		_ = binary.Write(buf, endianess.ByteOrder(), int64(n))
	}

	return buf.Bytes()[0:size]
}

func bytesToInt(b []byte, endianess Endianess) int {
	buf := bytes.NewBuffer(b)

	switch len(b) {
	case 1:
		var x int8
		_ = binary.Read(buf, endianess.ByteOrder(), &x)
		return int(x)
	case 2:
		var x int16
		_ = binary.Read(buf, endianess.ByteOrder(), &x)
		return int(x)
	case 4:
		var x int32
		_ = binary.Read(buf, endianess.ByteOrder(), &x)
		return int(x)
	default:
		var x int64
		_ = binary.Read(buf, endianess.ByteOrder(), &x)
		return int(x)
	}
}

func float32ToBytes(n float32, size int, endianess Endianess) []byte {
	buf := bytes.NewBuffer([]byte{})
	_ = binary.Write(buf, endianess.ByteOrder(), n)
	return buf.Bytes()[0:size]
}

func bytesToFloat32(b []byte, endianess Endianess) float32 {
	var x float32
	buf := bytes.NewBuffer(b)
	_ = binary.Read(buf, endianess.ByteOrder(), &x)
	return x
}

func float64ToBytes(n float64, size int, endianess Endianess) []byte {
	buf := bytes.NewBuffer([]byte{})
	_ = binary.Write(buf, endianess.ByteOrder(), n)
	return buf.Bytes()[0:size]
}

func bytesToFloat64(b []byte, endianess Endianess) float64 {
	var x float64
	buf := bytes.NewBuffer(b)
	_ = binary.Read(buf, endianess.ByteOrder(), &x)
	return x
}

func bytesToUint(b []byte) int {
	buf := bytes.NewBuffer(b)

	switch len(b) {
	case 1:
		var x uint8
		_ = binary.Read(buf, binary.LittleEndian, &x)
		return int(x)
	case 2:
		var x uint16
		_ = binary.Read(buf, binary.LittleEndian, &x)
		return int(x)
	case 4:
		var x uint32
		_ = binary.Read(buf, binary.LittleEndian, &x)
		return int(x)
	default:
		var x uint64
		_ = binary.Read(buf, binary.LittleEndian, &x)
		return int(x)
	}
}
