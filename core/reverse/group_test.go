package reverse

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"wscan/core/utils"
)

func TestGenerateHashedToken(t *testing.T) {
	tests := []struct {
		token   string
		groupID string
		unitID  string
	}{
		{"xxxx", "rsi0", "mkzn"},
		{"xxxx", "b5zi", "5czh"},
		{"test_token", "g1", "u1"},
		{"", "g1", "u1"},
		{"token", "", ""},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s_%s", tt.token, tt.groupID, tt.unitID), func(t *testing.T) {
			result := generateHashedToken(tt.token, tt.groupID, tt.unitID)
			if len(result) != 6 {
				t.Errorf("generateHashedToken result length = %d, want 6", len(result))
			}
			// Same inputs should always produce same output
			result2 := generateHashedToken(tt.token, tt.groupID, tt.unitID)
			if result != result2 {
				t.Errorf("generateHashedToken not deterministic: %s != %s", result, result2)
			}
		})
	}
}

func TestGenerateHashedTokenDifferentInputs(t *testing.T) {
	token1 := generateHashedToken("token", "g1", "u1")
	token2 := generateHashedToken("token", "g2", "u1")
	token3 := generateHashedToken("token", "g1", "u2")

	if token1 == token2 {
		t.Error("Different groupIDs should produce different tokens")
	}
	if token1 == token3 {
		t.Error("Different unitIDs should produce different tokens")
	}
}

func TestParseDomainInfo(t *testing.T) {
	tests := []struct {
		name        string
		domain      string
		mainDomain  string
		wantErr     bool
		hashedToken string
		groupID     string
		unitID      string
	}{
		{
			name:        "valid 4-part subdomain",
			domain:      "p-abc123-g1-u1.dnslog.com",
			mainDomain:  "dnslog.com",
			wantErr:     false,
			hashedToken: "abc123",
			groupID:     "g1",
			unitID:      "u1",
		},
		{
			name:        "valid 3-part subdomain",
			domain:      "p-abc123-g1.dnslog.com",
			mainDomain:  "dnslog.com",
			wantErr:     false,
			hashedToken: "abc123",
			groupID:     "g1",
			unitID:      "",
		},
		{
			name:       "wrong main domain",
			domain:     "p-abc123-g1-u1.other.com",
			mainDomain: "dnslog.com",
			wantErr:    true,
		},
		{
			name:       "too few parts",
			domain:     "p-abc.dnslog.com",
			mainDomain: "dnslog.com",
			wantErr:    true,
		},
		{
			name:       "domain same as mainDomain",
			domain:     "dnslog.com",
			mainDomain: "dnslog.com",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashedToken, groupID, unitID, _, err := parseDomainInfo(tt.domain, tt.mainDomain)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if hashedToken != tt.hashedToken {
				t.Errorf("hashedToken = %q, want %q", hashedToken, tt.hashedToken)
			}
			if groupID != tt.groupID {
				t.Errorf("groupID = %q, want %q", groupID, tt.groupID)
			}
			if unitID != tt.unitID {
				t.Errorf("unitID = %q, want %q", unitID, tt.unitID)
			}
		})
	}
}

func TestParseRmiURL(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		token   string
		groupID string
		unitID  string
	}{
		{
			// parseRmiURL requires 6 path segments: /a/b/c/d/e/f/ where fields[2]=token, fields[3]=groupID, fields[4]=unitID
			name:    "valid 6-segment rmi URL",
			rawURL:  "rmi://127.0.0.1:188/a/b/abc123/g1/u1/f/",
			token:   "abc123",
			groupID: "g1",
			unitID:  "u1",
		},
		{
			name:    "4-segment rmi URL returns empty",
			rawURL:  "rmi://127.0.0.1:188/i/abc123/g1/",
			token:   "",
			groupID: "",
			unitID:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashedToken, groupID, unitID, _, err := parseRmiURL(tt.rawURL)
			if err != nil {
				t.Fatalf("parseRmiURL error: %v", err)
			}
			if hashedToken != tt.token {
				t.Errorf("hashedToken = %q, want %q", hashedToken, tt.token)
			}
			if groupID != tt.groupID {
				t.Errorf("groupID = %q, want %q", groupID, tt.groupID)
			}
			if unitID != tt.unitID {
				t.Errorf("unitID = %q, want %q", unitID, tt.unitID)
			}
		})
	}
}

func TestParseRmiURLInvalid(t *testing.T) {
	_, _, _, _, err := parseRmiURL("://invalid")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestParsePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		token   string
		groupID string
		unitID  string
	}{
		{
			// 6-field path: /a/b/c/d/e/f/ → fields[2]=token, fields[3]=groupID, fields[4]=unitID
			name:    "6-field path",
			path:    "/a/b/abc123/g1/u1/f/",
			token:   "abc123",
			groupID: "g1",
			unitID:  "u1",
		},
		{
			// 4-field path: /a/abc123/g1/u1/ → fields[1]=token, fields[2]=groupID, fields[3]=unitID
			name:    "4-field path",
			path:    "/x/abc123/g1/u1/",
			token:   "abc123",
			groupID: "g1",
			unitID:  "u1",
		},
		{
			name:    "6-field path without trailing slash",
			path:    "/a/b/abc123/g1/u1/f",
			token:   "abc123",
			groupID: "g1",
			unitID:  "u1",
		},
		{
			name:    "3-field path returns empty (need 4 or 6)",
			path:    "/abc123/g1/u1/",
			token:   "",
			groupID: "",
			unitID:  "",
		},
		{
			name:    "short path returns empty",
			path:    "/abc/",
			token:   "",
			groupID: "",
			unitID:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashedToken, groupID, unitID, _, err := parsePath(tt.path)
			if err != nil {
				t.Fatalf("parsePath error: %v", err)
			}
			if hashedToken != tt.token {
				t.Errorf("hashedToken = %q, want %q", hashedToken, tt.token)
			}
			if groupID != tt.groupID {
				t.Errorf("groupID = %q, want %q", groupID, tt.groupID)
			}
			if unitID != tt.unitID {
				t.Errorf("unitID = %q, want %q", unitID, tt.unitID)
			}
		})
	}
}

func TestParseVisitURL(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		token   string
		groupID string
		unitID  string
	}{
		{
			name:    "valid visit URL",
			rawURL:  "http://127.0.0.1:88/i/abc123/g1/u1/",
			token:   "abc123",
			groupID: "g1",
			unitID:  "u1",
		},
		{
			name:    "visit URL without trailing slash",
			rawURL:  "http://127.0.0.1:88/i/abc123/g1/u1",
			token:   "abc123",
			groupID: "g1",
			unitID:  "u1",
		},
		{
			name:    "visit URL short path returns empty",
			rawURL:  "http://127.0.0.1:88/short",
			token:   "",
			groupID: "",
			unitID:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hashedToken, groupID, unitID, _, err := parseVisitURL(tt.rawURL)
			if err != nil {
				t.Fatalf("parseVisitURL error: %v", err)
			}
			if hashedToken != tt.token {
				t.Errorf("hashedToken = %q, want %q", hashedToken, tt.token)
			}
			if groupID != tt.groupID {
				t.Errorf("groupID = %q, want %q", groupID, tt.groupID)
			}
			if unitID != tt.unitID {
				t.Errorf("unitID = %q, want %q", unitID, tt.unitID)
			}
		})
	}
}

func TestParseVisitURLInvalid(t *testing.T) {
	_, _, _, _, err := parseVisitURL("://invalid")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func createTestReverse(t *testing.T) *Reverse {
	t.Helper()
	return &Reverse{
		config: &Config{
			Token: "testtoken",
			HTTPServerConfig: HTTPServerConfig{
				ListenIP:   "127.0.0.1",
				ListenPort: "8080",
			},
			DNSServerConfig: DNSServerConfig{
				Domain: "dnslog.com",
			},
		},
		internalGroupEventMap: &sync.Map{},
	}
}

func TestNewUnitGroup(t *testing.T) {
	r := createTestReverse(t)

	ug := r.NewUnitGroup()
	if ug == nil {
		t.Fatal("NewUnitGroup returned nil")
	}
	if ug.id == "" {
		t.Error("UnitGroup id should not be empty")
	}
	if len(ug.id) != 4 {
		t.Errorf("UnitGroup id length = %d, want 4", len(ug.id))
	}
	if ug.expireAt.IsZero() {
		t.Error("UnitGroup expireAt should not be zero")
	}
}

func TestRegister(t *testing.T) {
	r := createTestReverse(t)

	unit := r.Register("test_data")
	if unit == nil {
		t.Fatal("Register returned nil")
	}
	if unit.id == "" {
		t.Error("Unit id should not be empty")
	}
	if len(unit.id) != 4 {
		t.Errorf("Unit id length = %d, want 4", len(unit.id))
	}
	if unit.Data != "test_data" {
		t.Errorf("Unit Data = %v, want 'test_data'", unit.Data)
	}
	if unit.group == nil {
		t.Error("Unit group should not be nil")
	}
	if unit.reverse != r {
		t.Error("Unit reverse should point to the Reverse instance")
	}
}

func TestRegisterWithGroup(t *testing.T) {
	r := createTestReverse(t)
	ug := r.NewUnitGroup()

	unit := r.RegisterWithGroup("test_data", ug)
	if unit == nil {
		t.Fatal("RegisterWithGroup returned nil")
	}
	if unit.group != ug {
		t.Error("Unit group should be the same UnitGroup")
	}
}

func TestRegisterNilData(t *testing.T) {
	r := createTestReverse(t)

	unit := r.Register(nil)
	if unit == nil {
		t.Fatal("Register with nil data should not return nil")
	}
	if unit.Data != nil {
		t.Error("Unit Data should be nil")
	}
}

func TestUnitGetEncodedVisitURL(t *testing.T) {
	r := createTestReverse(t)
	unit := r.Register(nil)

	url, err := unit.GetEncodedVisitURL()
	if err != nil {
		t.Fatalf("GetEncodedVisitURL error: %v", err)
	}
	if url == "" {
		t.Error("GetEncodedVisitURL returned empty string")
	}
	if !strings.HasPrefix(url, "http://") {
		t.Errorf("URL should start with http://, got %s", url)
	}
	// URL should contain the group and unit IDs
	if !strings.Contains(url, unit.group.id) {
		t.Errorf("URL should contain group id %s, got %s", unit.group.id, url)
	}
	if !strings.Contains(url, unit.id) {
		t.Errorf("URL should contain unit id %s, got %s", unit.id, url)
	}
}

func TestUnitGetQueryDomain(t *testing.T) {
	r := createTestReverse(t)
	unit := r.Register(nil)

	di, err := unit.GetQueryDomain()
	if err != nil {
		t.Fatalf("GetQueryDomain error: %v", err)
	}
	if di == nil {
		t.Fatal("GetQueryDomain returned nil")
	}
	if di.Domain == "" {
		t.Error("Domain should not be empty")
	}
	if !strings.HasSuffix(di.Domain, "dnslog.com") {
		t.Errorf("Domain should end with dnslog.com, got %s", di.Domain)
	}
	// Domain should start with "p-"
	if !strings.HasPrefix(di.Domain, "p-") {
		t.Errorf("Domain should start with 'p-', got %s", di.Domain)
	}
}

func TestUnitGetQueryDomainWithDNSServerIP(t *testing.T) {
	r := createTestReverse(t)
	r.config.ClientConfig.DNSServerIP = "8.8.8.8"
	unit := r.Register(nil)

	di, err := unit.GetQueryDomain()
	if err != nil {
		t.Fatalf("GetQueryDomain error: %v", err)
	}
	if !di.IsDomainNameServer {
		t.Error("IsDomainNameServer should be true when DNSServerIP is set")
	}
}

func TestUnitGetRmiURL(t *testing.T) {
	r := createTestReverse(t)
	unit := r.Register(nil)

	rmiURL := unit.GetRmiURL()
	if rmiURL == "" {
		t.Error("GetRmiURL returned empty string")
	}
	if !strings.HasPrefix(rmiURL, "rmi://") {
		t.Errorf("RMI URL should start with rmi://, got %s", rmiURL)
	}
}

func TestUnitGetLdapURL(t *testing.T) {
	r := createTestReverse(t)
	unit := r.Register(nil)

	ldapURL := unit.GetLdapURL()
	if ldapURL == "" {
		t.Error("GetLdapURL returned empty string")
	}
	if !strings.HasPrefix(ldapURL, "ldap://") {
		t.Errorf("LDAP URL should start with ldap://, got %s", ldapURL)
	}
}

func TestUnitGetVisitURL(t *testing.T) {
	r := createTestReverse(t)
	unit := r.Register(nil)

	visitURL := unit.GetVisitURL()
	if visitURL == "" {
		t.Error("GetVisitURL returned empty string")
	}
	if !strings.HasPrefix(visitURL, "http://") {
		t.Errorf("Visit URL should start with http://, got %s", visitURL)
	}
}

func TestUnitOnVisit(t *testing.T) {
	r := createTestReverse(t)
	unit := r.Register(nil)

	called := false
	unit.OnVisit(func(ev *Event) error {
		called = true
		return nil
	})

	if unit.Callback == nil {
		t.Error("Callback should be set after OnVisit")
	}

	// Call the callback manually to verify it works
	unit.Callback(&Event{GroupID: "test"})
	if !called {
		t.Error("Callback should have been called")
	}
}

func TestUnitFetch(t *testing.T) {
	r := createTestReverse(t)
	unit := r.Register(nil)

	err := unit.Fetch(0)
	if err != nil {
		t.Fatalf("Fetch error: %v", err)
	}

	// After fetch, the unit should be in the callback map
	key := fmt.Sprintf("%s_%s", unit.group.id, unit.id)
	_, loaded := r.groupUnitCallbackMap.Load(key)
	if !loaded {
		t.Error("Unit should be in groupUnitCallbackMap after Fetch")
	}
}

func TestUnitGroupJoin(t *testing.T) {
	r := createTestReverse(t)
	ug := r.NewUnitGroup()

	unit1 := r.RegisterWithGroup(nil, ug)
	unit2 := r.RegisterWithGroup(nil, ug)

	ug.Join(unit1)
	ug.Join(unit2)

	// Verify units are in the group
	_, loaded1 := ug.units.Load(unit1.id)
	_, loaded2 := ug.units.Load(unit2.id)
	if !loaded1 {
		t.Error("unit1 should be in the UnitGroup after Join")
	}
	if !loaded2 {
		t.Error("unit2 should be in the UnitGroup after Join")
	}
}

func TestUnitGroupFetch(t *testing.T) {
	r := createTestReverse(t)
	ug := r.NewUnitGroup()

	beforeFetch := ug.expireAt
	ug.fetch(0)

	// After fetch, expireAt should be updated
	// Note: fetch sets expireAt to Now+2min, while NewUnitGroup sets it to Now+5min
	// So expireAt will be different (not After, but still updated)
	if ug.expireAt.Equal(beforeFetch) {
		t.Error("expireAt should be updated after fetch")
	}
}

func TestUnitURLConsistency(t *testing.T) {
	r := createTestReverse(t)
	unit := r.Register(nil)

	// GetEncodedVisitURL and GetVisitURL should produce the same URL
	encodedURL, _ := unit.GetEncodedVisitURL()
	visitURL := unit.GetVisitURL()

	if encodedURL != visitURL {
		t.Errorf("GetEncodedVisitURL and GetVisitURL should be the same, got %q and %q", encodedURL, visitURL)
	}
}

func TestUnitURLContainsHashedToken(t *testing.T) {
	r := createTestReverse(t)
	unit := r.Register(nil)

	expectedToken := generateHashedToken(r.config.Token, unit.group.id, unit.id)
	visitURL := unit.GetVisitURL()

	if !strings.Contains(visitURL, expectedToken) {
		t.Errorf("Visit URL should contain hashed token %s, got %s", expectedToken, visitURL)
	}
}

func TestMultipleRegisterCreatesDifferentGroups(t *testing.T) {
	r := createTestReverse(t)

	unit1 := r.Register(nil)
	unit2 := r.Register(nil)

	if unit1.group.id == unit2.group.id {
		t.Error("Different Register calls should create different group IDs")
	}
}

func TestRegisterWithSameGroup(t *testing.T) {
	r := createTestReverse(t)
	ug := r.NewUnitGroup()

	unit1 := r.RegisterWithGroup(nil, ug)
	unit2 := r.RegisterWithGroup(nil, ug)

	if unit1.group.id != unit2.group.id {
		t.Error("RegisterWithGroup with same group should share the group ID")
	}
	if unit1.id == unit2.id {
		t.Error("Different units should have different IDs")
	}
}

func TestParseDomainInfoWithOOBData(t *testing.T) {
	// Test with a 2-part prefix that includes oob data
	domain := "p-abc123-g1-u1.oob.dnslog.com"
	hashedToken, groupID, unitID, oobData, err := parseDomainInfo(domain, "dnslog.com")
	if err != nil {
		t.Fatalf("parseDomainInfo error: %v", err)
	}
	if hashedToken != "abc123" {
		t.Errorf("hashedToken = %q, want %q", hashedToken, "abc123")
	}
	if groupID != "g1" {
		t.Errorf("groupID = %q, want %q", groupID, "g1")
	}
	if unitID != "u1" {
		t.Errorf("unitID = %q, want %q", unitID, "u1")
	}
	if oobData != "oob" {
		t.Errorf("oobData = %q, want %q", oobData, "oob")
	}
}

func TestParseDomainInfoTrailingDot(t *testing.T) {
	domain := "p-abc123-g1-u1.dnslog.com."
	hashedToken, groupID, unitID, _, err := parseDomainInfo(domain, "dnslog.com")
	if err != nil {
		t.Fatalf("parseDomainInfo with trailing dot error: %v", err)
	}
	if hashedToken != "abc123" {
		t.Errorf("hashedToken = %q, want %q", hashedToken, "abc123")
	}
	if groupID != "g1" {
		t.Errorf("groupID = %q, want %q", groupID, "g1")
	}
	if unitID != "u1" {
		t.Errorf("unitID = %q, want %q", unitID, "u1")
	}
}

func TestParsePathEdgeCases(t *testing.T) {
	// Empty path
	_, _, _, _, _ = parsePath("")

	// Single slash
	_, _, _, _, _ = parsePath("/")

	// 3-field path doesn't match 4 or 6 field format, returns empty
	token, groupID, unitID, _, _ := parsePath("/abc/g1/u1/")
	if token != "" || groupID != "" || unitID != "" {
		t.Errorf("parsePath(/abc/g1/u1/) = %q/%q/%q, want empty (3 fields not matched)", token, groupID, unitID)
	}
}

// Test that utils.RandLowLetterNumber is used correctly
func TestNewUnitGroupRandomID(t *testing.T) {
	r := createTestReverse(t)

	ug1 := r.NewUnitGroup()
	ug2 := r.NewUnitGroup()

	if ug1.id == ug2.id {
		t.Error("Two UnitGroups should have different random IDs")
	}
}

func TestRegisterRandomUnitID(t *testing.T) {
	r := createTestReverse(t)

	unit1 := r.Register(nil)
	unit2 := r.Register(nil)

	if unit1.id == unit2.id {
		t.Error("Two units should have different random IDs")
	}
}

// Ensure utils import is used
var _ = utils.RandLowLetterNumber

// Ensure time import is used
var _ = time.Now
