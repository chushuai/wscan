package checker

import (
	"testing"
)

func TestGetURLPort_ExplicitPort(t *testing.T) {
	port, err := GetURLPort("http://example.com:8080/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if port != 8080 {
		t.Errorf("GetURLPort() = %d, expected 8080", port)
	}
}

func TestGetURLPort_DefaultHTTP(t *testing.T) {
	port, err := GetURLPort("http://example.com/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if port != 80 {
		t.Errorf("GetURLPort() = %d, expected 80", port)
	}
}

func TestGetURLPort_DefaultHTTPS(t *testing.T) {
	port, err := GetURLPort("https://example.com/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if port != 443 {
		t.Errorf("GetURLPort() = %d, expected 443", port)
	}
}

func TestGetURLPort_InvalidURL(t *testing.T) {
	_, err := GetURLPort("://invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestGetURLPort_UnsupportedScheme(t *testing.T) {
	_, err := GetURLPort("ftp://example.com/path")
	if err == nil {
		t.Error("expected error for unsupported scheme")
	}
}

func TestGetURLPort_HTTPSExplicitPort(t *testing.T) {
	port, err := GetURLPort("https://example.com:8443/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if port != 8443 {
		t.Errorf("GetURLPort() = %d, expected 8443", port)
	}
}

func TestGetQueryKeys(t *testing.T) {
	keys, err := GetQueryKeys("http://example.com/path?id=1&name=test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 query keys, got %d", len(keys))
	}
	// Keys may be in any order
	keyMap := make(map[string]bool)
	for _, k := range keys {
		keyMap[k] = true
	}
	if !keyMap["id"] {
		t.Error("expected 'id' in query keys")
	}
	if !keyMap["name"] {
		t.Error("expected 'name' in query keys")
	}
}

func TestGetQueryKeys_NoQuery(t *testing.T) {
	keys, err := GetQueryKeys("http://example.com/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 query keys, got %d", len(keys))
	}
}

func TestGetQueryKeys_InvalidURL(t *testing.T) {
	_, err := GetQueryKeys("://invalid")
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

func TestGetQueryKeys_EmptyValue(t *testing.T) {
	keys, err := GetQueryKeys("http://example.com/path?id=&name=test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 query keys, got %d", len(keys))
	}
}

func TestGetQueryKeys_SingleKey(t *testing.T) {
	keys, err := GetQueryKeys("http://example.com/path?id=42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 || keys[0] != "id" {
		t.Errorf("expected ['id'], got %v", keys)
	}
}
