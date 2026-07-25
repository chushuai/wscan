package checker

import (
	"testing"

	"wscan/core/utils/checker/filter"
	"wscan/core/utils/checker/matcher"
)

func TestServiceChecker_Close(t *testing.T) {
	sc := &ServiceChecker{}
	err := sc.Close()
	if err != nil {
		t.Errorf("Close() returned unexpected error: %v", err)
	}
}

func TestServiceChecker_Reset(t *testing.T) {
	sc := &ServiceChecker{}
	err := sc.Reset()
	if err != nil {
		t.Errorf("Reset() returned unexpected error: %v", err)
	}
}

func TestServiceChecker_IsInserted(t *testing.T) {
	sc := &ServiceChecker{}
	result := sc.IsInserted("anykey", true)
	if !result {
		t.Error("IsInserted() should return true (always returns true)")
	}
}

func TestServiceChecker_IsInsertedWithTTL(t *testing.T) {
	sc := &ServiceChecker{}
	result := sc.IsInsertedWithTTL("anykey", true, 0)
	if !result {
		t.Error("IsInsertedWithTTL() should return true (always returns true)")
	}
}

func TestServiceChecker_Insert(t *testing.T) {
	sc := &ServiceChecker{}
	// Insert doesn't panic
	sc.Insert("key")
}

func TestServiceChecker_InsertWithTTL(t *testing.T) {
	sc := &ServiceChecker{}
	// InsertWithTTL doesn't panic
	sc.InsertWithTTL("key", 100)
}

func TestServiceChecker_DisableAutoInsert(t *testing.T) {
	sc := &ServiceChecker{}
	sc.DisableAutoInsert()
	// No-op, just verify it doesn't panic
}

func TestServiceChecker_AddScope(t *testing.T) {
	sc := &ServiceChecker{}
	sc.AddScope()
	// No-op, just verify it doesn't panic
}

func TestServiceChecker_NewSubChecker(t *testing.T) {
	sc := &ServiceChecker{}
	sc.NewSubChecker()
	// No-op, just verify it doesn't panic
}

func TestServiceChecker_Target(t *testing.T) {
	sc := &ServiceChecker{}
	sc.Target()
	// No-op, just verify it doesn't panic
}

func TestServiceChecker_WithTTL(t *testing.T) {
	sc := &ServiceChecker{}
	sc.WithTTL()
	// No-op, just verify it doesn't panic
}

func TestServicePattern_Bool(t *testing.T) {
	sp := &ServicePattern{}
	if !sp.Bool() {
		t.Error("ServicePattern.Bool() should always return true")
	}
}

func TestServicePattern_Error(t *testing.T) {
	sp := &ServicePattern{}
	if sp.Error() != nil {
		t.Errorf("ServicePattern.Error() = %v, expected nil", sp.Error())
	}
}

func TestServicePattern_AddScope(t *testing.T) {
	sp := &ServicePattern{}
	sp.AddScope()
}

func TestServicePattern_DisableAutoInsert(t *testing.T) {
	sp := &ServicePattern{}
	sp.DisableAutoInsert()
}

func TestServicePattern_IsAllowed(t *testing.T) {
	sp := &ServicePattern{}
	sp.IsAllowed()
}

func TestServicePattern_IsNewService(t *testing.T) {
	sp := &ServicePattern{}
	sp.IsNewService()
}

func TestServicePattern_WithTTL(t *testing.T) {
	sp := &ServicePattern{}
	sp.WithTTL()
}

func TestServiceCheckerConfig(t *testing.T) {
	config := &ServiceCheckerConfig{
		HostnameAllowed:    []string{"example.com"},
		HostnameDisallowed: []string{"evil.com"},
		TCPPortAllowed:     []string{"80", "443"},
		TCPPortDisallowed:  []string{"22"},
		UDPPortAllowed:     []string{"53"},
		UDPPortDisallowed:  []string{"161"},
	}

	if len(config.HostnameAllowed) != 1 || config.HostnameAllowed[0] != "example.com" {
		t.Error("HostnameAllowed not set correctly")
	}
	if len(config.TCPPortAllowed) != 2 {
		t.Error("TCPPortAllowed not set correctly")
	}
}

func TestServiceChecker_WithMatchers(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	config := &ServiceCheckerConfig{
		HostnameAllowed:    []string{"example.com"},
		HostnameDisallowed: []string{"evil.com"},
		TCPPortAllowed:     []string{"80"},
		TCPPortDisallowed:  []string{"22"},
	}

	sc := &ServiceChecker{
		Filter:                    sf,
		config:                    config,
		HostnameAllowedMatcher:    matcher.NewHostsMatcher(),
		HostnameDisallowedMatcher: matcher.NewHostsMatcher(),
		TCPPortAllowedMatcher:     matcher.NewPortMatcher(),
		TCPPortDisallowedMatcher:  matcher.NewPortMatcher(),
		UDPPortAllowedMatcher:     matcher.NewPortMatcher(),
		UDPPortDisallowedMatcher:  matcher.NewPortMatcher(),
	}

	// Initialize matchers
	sc.HostnameAllowedMatcher.Add(config.HostnameAllowed)
	sc.HostnameDisallowedMatcher.Add(config.HostnameDisallowed)
	sc.TCPPortAllowedMatcher.Add(config.TCPPortAllowed)
	sc.TCPPortDisallowedMatcher.Add(config.TCPPortDisallowed)

	// Test matcher functionality
	if sc.HostnameAllowedMatcher.IsEmpty() {
		t.Error("HostnameAllowedMatcher should not be empty after Add")
	}
	if !sc.HostnameAllowedMatcher.Match("example.com") {
		t.Error("HostnameAllowedMatcher should match 'example.com'")
	}
	if sc.HostnameAllowedMatcher.Match("other.com") {
		t.Error("HostnameAllowedMatcher should not match 'other.com'")
	}
	if sc.TCPPortAllowedMatcher.IsEmpty() {
		t.Error("TCPPortAllowedMatcher should not be empty after Add")
	}
	if !sc.TCPPortAllowedMatcher.Match("80") {
		t.Error("TCPPortAllowedMatcher should match port 80")
	}
}

func TestServicePattern_Fields(t *testing.T) {
	sf := filter.NewSyncMapFilter()
	sc := &ServiceChecker{
		Filter:             sf,
		Scope:              "test_scope",
		AutoInsertDisabled: true,
		TTL:                3600,
	}

	sp := &ServicePattern{
		Checker:            sc,
		TransportProtocol:  6, // TCP
		Hostname:           "example.com",
		Port:               "80",
		Scope:              "test_scope",
		AutoInsertDisabled: true,
		TTL:                3600,
	}

	if sp.Checker != sc {
		t.Error("ServicePattern.Checker not set correctly")
	}
	if sp.TransportProtocol != 6 {
		t.Error("ServicePattern.TransportProtocol not set correctly")
	}
	if sp.Hostname != "example.com" {
		t.Error("ServicePattern.Hostname not set correctly")
	}
	if sp.Port != "80" {
		t.Error("ServicePattern.Port not set correctly")
	}
	if sp.Scope != "test_scope" {
		t.Error("ServicePattern.Scope not set correctly")
	}
	if !sp.AutoInsertDisabled {
		t.Error("ServicePattern.AutoInsertDisabled not set correctly")
	}
	if sp.TTL != 3600 {
		t.Error("ServicePattern.TTL not set correctly")
	}
}
