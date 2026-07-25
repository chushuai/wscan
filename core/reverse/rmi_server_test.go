package reverse

import (
	"sync"
	"testing"
)

func TestCheckRMIValid(t *testing.T) {
	// JRMI with version 0x01 and protocol 0x4b (StreamProtocol)
	data := []byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x01, 0x4b, 0x00}
	if !checkRMI(data) {
		t.Error("checkRMI should return true for valid JRMI header")
	}
}

func TestCheckRMIValidVersion2(t *testing.T) {
	// JRMI with version 0x02
	data := []byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x02, 0x4b, 0x00}
	if !checkRMI(data) {
		t.Error("checkRMI should return true for version 2")
	}
}

func TestCheckRMIValidProtocolL(t *testing.T) {
	// Protocol 0x4c (SingleOpProtocol)
	data := []byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x01, 0x4c, 0x00}
	if !checkRMI(data) {
		t.Error("checkRMI should return true for protocol L")
	}
}

func TestCheckRMIValidProtocolM(t *testing.T) {
	// Protocol 0x4d (MultiplexProtocol)
	data := []byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x01, 0x4d, 0x00}
	if !checkRMI(data) {
		t.Error("checkRMI should return true for protocol M")
	}
}

func TestCheckRMIInvalidMagic(t *testing.T) {
	// Wrong magic bytes
	data := []byte{0x00, 0x52, 0x4d, 0x49, 0x00, 0x01, 0x4b, 0x00}
	if checkRMI(data) {
		t.Error("checkRMI should return false for wrong magic")
	}
}

func TestCheckRMIInvalidVersion(t *testing.T) {
	// Invalid version (0x03)
	data := []byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x03, 0x4b, 0x00}
	if checkRMI(data) {
		t.Error("checkRMI should return false for invalid version")
	}
}

func TestCheckRMIInvalidProtocol(t *testing.T) {
	// Invalid protocol (0x4e)
	data := []byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x01, 0x4e, 0x00}
	if checkRMI(data) {
		t.Error("checkRMI should return false for invalid protocol")
	}
}

func TestCheckRMINonZeroPadding(t *testing.T) {
	// Non-zero byte in padding area
	data := []byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x01, 0x4b, 0x01}
	if checkRMI(data) {
		t.Error("checkRMI should return false for non-zero padding")
	}
}

func TestCheckRMITooShort(t *testing.T) {
	// Too short data
	data := []byte{0x4a, 0x52, 0x4d, 0x49}
	if checkRMI(data) {
		t.Error("checkRMI should return false for short data")
	}
}

func TestCheckRMIEmpty(t *testing.T) {
	if checkRMI([]byte{}) {
		t.Error("checkRMI should return false for empty data")
	}
}

func TestCheckRMIExactly8Bytes(t *testing.T) {
	// Exactly 8 bytes - minimum valid length
	data := []byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x01, 0x4b, 0x00}
	if !checkRMI(data) {
		t.Error("checkRMI should return true for valid 8-byte data")
	}
}

func TestCheckRMILongerWithZeroPadding(t *testing.T) {
	// Longer data with all-zero padding
	data := []byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x01, 0x4b, 0x00, 0x00, 0x00, 0x00}
	if !checkRMI(data) {
		t.Error("checkRMI should return true for valid data with zero padding")
	}
}

func TestLdapPathLength(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		expected int
	}{
		{
			name:     "valid path length",
			buf:      makeBufWithPathLength(5),
			expected: 5,
		},
		{
			name:     "zero length",
			buf:      makeBufWithPathLength(0),
			expected: 0,
		},
		{
			name:     "buffer too short",
			buf:      []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			expected: 0,
		},
		{
			name:     "empty buffer",
			buf:      []byte{},
			expected: 0,
		},
		{
			name:     "nil buffer",
			buf:      nil,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ldapPathLength(tt.buf)
			if result != tt.expected {
				t.Errorf("ldapPathLength = %d, want %d", result, tt.expected)
			}
		})
	}
}

func makeBufWithPathLength(length byte) []byte {
	buf := make([]byte, 9+int(length))
	buf[8] = length
	// Fill path bytes with 'A'
	for i := 0; i < int(length); i++ {
		buf[9+i] = 'A'
	}
	return buf
}

func TestLdapPathLengthValidPath(t *testing.T) {
	// Create a buffer with a valid path
	path := "/i/abc/g1/u1/"
	buf := make([]byte, 256)
	buf[8] = byte(len(path))
	copy(buf[9:], path)

	result := ldapPathLength(buf)
	if result != len(path) {
		t.Errorf("ldapPathLength = %d, want %d", result, len(path))
	}
}

func TestNewRMIServer(t *testing.T) {
	config := &Config{Token: "test"}
	internalGroupEventMap := &sync.Map{}
	db := helperDB(t)
	defer db.Close()

	server := NewRMIServer(config, internalGroupEventMap, db)
	if server == nil {
		t.Fatal("NewRMIServer returned nil")
	}
	if server.config != config {
		t.Error("RMIServer config should match")
	}
	if server.db != db {
		t.Error("RMIServer db should match")
	}
}

func TestRMIServerClose(t *testing.T) {
	config := &Config{Token: "test"}
	internalGroupEventMap := &sync.Map{}
	db := helperDB(t)
	defer db.Close()

	server := NewRMIServer(config, internalGroupEventMap, db)

	// Close with nil listener should not panic
	err := server.Close()
	if err != nil {
		t.Errorf("Close with nil listener should return nil, got %v", err)
	}
}

func TestRMIServerStart(t *testing.T) {
	config := &Config{Token: "test"}
	internalGroupEventMap := &sync.Map{}
	db := helperDB(t)
	defer db.Close()

	server := NewRMIServer(config, internalGroupEventMap, db)

	// Start is a no-op, just verify it doesn't panic
	server.Start()
}

func TestRmiServerCheckAndPrepare(t *testing.T) {
	// rmiServerCheckAndPrepare is a no-op, just verify it doesn't panic
	rmiServerCheckAndPrepare()
}

func TestHandleRMIConn(t *testing.T) {
	// handleRMIConn is a no-op, just verify it doesn't panic
	handleRMIConn()
}

func TestLdapFingerAndReply(t *testing.T) {
	// Test the ldapfinger constant
	if ldapfinger != "300c020101600702010304008000" {
		t.Errorf("ldapfinger = %q, want %q", ldapfinger, "300c020101600702010304008000")
	}

	// Test the ldapreply constant
	expectedReply := []byte{
		0x30, 0x0c,
		0x02, 0x01, 0x01,
		0x61, 0x07,
		0x0a, 0x01, 0x00,
		0x04, 0x00,
		0x04, 0x00,
	}
	if len(ldapreply) != len(expectedReply) {
		t.Fatalf("ldapreply length = %d, want %d", len(ldapreply), len(expectedReply))
	}
	for i, b := range ldapreply {
		if b != expectedReply[i] {
			t.Errorf("ldapreply[%d] = 0x%02x, want 0x%02x", i, b, expectedReply[i])
		}
	}
}

func TestRmireplayConstant(t *testing.T) {
	// Test the rmireplay constant
	expectedRmireplay := []byte{
		0x4e, 0x00, 0x09,
		0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31,
		0x00, 0x00, 0xc4, 0x12,
	}
	if len(rmireplay) != len(expectedRmireplay) {
		t.Fatalf("rmireplay length = %d, want %d", len(rmireplay), len(expectedRmireplay))
	}
	for i, b := range rmireplay {
		if b != expectedRmireplay[i] {
			t.Errorf("rmireplay[%d] = 0x%02x, want 0x%02x", i, b, expectedRmireplay[i])
		}
	}
}

func TestCheckRMIAllProtocols(t *testing.T) {
	protocols := []byte{0x4b, 0x4c, 0x4d}
	for _, proto := range protocols {
		data := []byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x01, proto, 0x00}
		if !checkRMI(data) {
			t.Errorf("checkRMI should return true for protocol 0x%02x", proto)
		}
	}
}

func TestCheckRMIInvalidProtocols(t *testing.T) {
	invalidProtocols := []byte{0x4a, 0x4e, 0x50, 0x00, 0xff}
	for _, proto := range invalidProtocols {
		data := []byte{0x4a, 0x52, 0x4d, 0x49, 0x00, 0x01, proto, 0x00}
		if checkRMI(data) {
			t.Errorf("checkRMI should return false for protocol 0x%02x", proto)
		}
	}
}
