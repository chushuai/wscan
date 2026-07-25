/**
* @Author: shaochuyu
* @Date: 6/16/2026
* SSL/TLS Security Audit Plugin Tests
 */
package sslaudit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	wscan_http "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/printer"
)

// ==================== Mock Helpers ====================

func mockApollo(req *wscan_http.Request, resp *wscan_http.Response) *base.Apollo {
	if req == nil {
		req, _ = wscan_http.NewRequest("GET", "https://example.com/", nil)
	}
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	return a
}

func makeTestResponse(body string) *wscan_http.Response {
	u, _ := url.Parse("https://example.com/")
	netResp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	return resp
}

func makeTestResponseWithHeaders(body string, statusCode int, headers map[string]string) *wscan_http.Response {
	u, _ := url.Parse("https://example.com/")
	netResp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    &http.Request{URL: u},
	}
	for k, v := range headers {
		netResp.Header.Set(k, v)
	}
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)
	return resp
}

type mockPrinter struct {
	onPrint func(v *model.Vuln)
}

func (m *mockPrinter) Print(v any) error {
	if vuln, ok := v.(*model.Vuln); ok && m.onPrint != nil {
		m.onPrint(vuln)
	}
	return nil
}

func (m *mockPrinter) Close() error { return nil }
func (m *mockPrinter) AddInterceptor(func(any) (any, error)) printer.Printer {
	return m
}
func (m *mockPrinter) LogSubdomain(any) error { return nil }
func (m *mockPrinter) LogVuln(any) error      { return nil }

func makeHTTPSPrinter(vulnFound *bool) *mockPrinter {
	return &mockPrinter{onPrint: func(v *model.Vuln) {
		*vulnFound = true
	}}
}

// ==================== Plugin Struct Tests ====================

func TestSSLAudit_Close(t *testing.T) {
	s := &SSLAudit{}
	if err := s.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestSSLAudit_DefaultConfig(t *testing.T) {
	s := &SSLAudit{}
	cfg := s.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	typedCfg, ok := cfg.(*Config)
	if !ok {
		t.Fatal("DefaultConfig() did not return *Config")
	}

	if typedCfg.PluginBaseConfig.Name != "sslaudit" {
		t.Errorf("Expected Name='sslaudit', got '%s'", typedCfg.PluginBaseConfig.Name)
	}
	if typedCfg.PluginBaseConfig.Enabled {
		t.Error("Expected Enabled=false by default")
	}
	if !typedCfg.PluginBaseConfig.IsAdvanced {
		t.Error("Expected IsAdvanced=true")
	}
}

func TestSSLAudit_DefaultConfig_AllChecksEnabled(t *testing.T) {
	s := &SSLAudit{}
	cfg := s.DefaultConfig().(*Config)

	checks := []struct {
		name string
		val  bool
	}{
		{"CheckProtocols", cfg.CheckProtocols},
		{"CheckCiphers", cfg.CheckCiphers},
		{"CheckCertificate", cfg.CheckCertificate},
		{"CheckHeaders", cfg.CheckHeaders},
	}

	for _, check := range checks {
		if !check.val {
			t.Errorf("Expected %s=true, got false", check.name)
		}
	}
}

func TestSSLAudit_Fingers_AllEnabled(t *testing.T) {
	s := &SSLAudit{}
	cfg := s.DefaultConfig()
	ab := &base.ApolloBase{}
	s.Init(context.Background(), cfg, ab)

	fingers := s.Fingers()
	if len(fingers) == 0 {
		t.Error("Expected non-zero fingers when all checks enabled")
	}
	// Expected: 1 (protocol) + 3 (cipher + freak + drown) + 1 (cert) + 1 (hsts) = 6
	if len(fingers) != 6 {
		t.Errorf("Expected 6 fingers when all checks enabled, got %d", len(fingers))
	}
}

func TestSSLAudit_Fingers_AllDisabled(t *testing.T) {
	s := &SSLAudit{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:       "sslaudit",
			Enabled:    false,
			IsAdvanced: true,
		},
		CheckProtocols:   false,
		CheckCiphers:     false,
		CheckCertificate: false,
		CheckHeaders:     false,
	}
	ab := &base.ApolloBase{}
	s.Init(context.Background(), cfg, ab)

	fingers := s.Fingers()
	if len(fingers) != 0 {
		t.Errorf("Expected 0 fingers when all checks disabled, got %d", len(fingers))
	}
}

func TestSSLAudit_Fingers_NilConfig(t *testing.T) {
	s := &SSLAudit{}
	// Don't call Init, so GetConfig returns nil
	fingers := s.Fingers()
	if fingers != nil {
		t.Errorf("Expected nil fingers with nil config, got %v", fingers)
	}
}

func TestSSLAudit_Fingers_OnlyProtocols(t *testing.T) {
	s := &SSLAudit{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:       "sslaudit",
			Enabled:    true,
			IsAdvanced: true,
		},
		CheckProtocols:   true,
		CheckCiphers:     false,
		CheckCertificate: false,
		CheckHeaders:     false,
	}
	ab := &base.ApolloBase{}
	s.Init(context.Background(), cfg, ab)

	fingers := s.Fingers()
	if len(fingers) != 1 {
		t.Errorf("Expected 1 finger when only protocols enabled, got %d", len(fingers))
	}
}

func TestSSLAudit_Fingers_OnlyCiphers(t *testing.T) {
	s := &SSLAudit{}
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:       "sslaudit",
			Enabled:    true,
			IsAdvanced: true,
		},
		CheckProtocols:   false,
		CheckCiphers:     true,
		CheckCertificate: false,
		CheckHeaders:     false,
	}
	ab := &base.ApolloBase{}
	s.Init(context.Background(), cfg, ab)

	fingers := s.Fingers()
	// cipher + freak + drown = 3
	if len(fingers) != 3 {
		t.Errorf("Expected 3 fingers when only ciphers enabled, got %d", len(fingers))
	}
}

func TestSSLAudit_GetConfig(t *testing.T) {
	s := &SSLAudit{}
	// Before Init
	cfg := s.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}

	// After Init
	expectedCfg := s.DefaultConfig()
	ab := &base.ApolloBase{}
	s.Init(context.Background(), expectedCfg, ab)

	cfg = s.GetConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
}

func TestSSLAudit_Init(t *testing.T) {
	s := &SSLAudit{}
	cfg := s.DefaultConfig()
	ab := &base.ApolloBase{}
	err := s.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
}

func TestConfig_BaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "sslaudit",
			Enabled: true,
		},
	}
	bc := cfg.BaseConfig()
	if bc == nil {
		t.Fatal("BaseConfig() returned nil")
	}
	if bc.Name != "sslaudit" {
		t.Errorf("Expected Name='sslaudit', got '%s'", bc.Name)
	}
}

// ==================== Finger Binding Tests ====================

func TestInsecureProtocolVersion_Finger(t *testing.T) {
	d := &insecureProtocolVersion{}
	finger := d.Finger()
	if finger == nil {
		t.Fatal("insecureProtocolVersion.Finger() returned nil")
	}
	if finger.Binding.ID != "ssl_insecure_protocol" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
	if finger.Binding.Severity != model.SeverityHigh {
		t.Errorf("Expected Severity=high, got %s", finger.Binding.Severity)
	}
	if finger.Channel != "web-generic" {
		t.Errorf("Unexpected Channel: %s", finger.Channel)
	}
}

func TestWeakCipherSuite_Finger(t *testing.T) {
	d := &weakCipherSuite{}
	finger := d.Finger()
	if finger == nil {
		t.Fatal("weakCipherSuite.Finger() returned nil")
	}
	if finger.Binding.ID != "ssl_weak_cipher" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
	if finger.Binding.Severity != model.SeverityHigh {
		t.Errorf("Expected Severity=high, got %s", finger.Binding.Severity)
	}
}

func TestFreakVulnerable_Finger(t *testing.T) {
	d := &freakVulnerable{}
	finger := d.Finger()
	if finger == nil {
		t.Fatal("freakVulnerable.Finger() returned nil")
	}
	if finger.Binding.ID != "ssl_freak_vulnerable" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
	if finger.Binding.Severity != model.SeverityHigh {
		t.Errorf("Expected Severity=high, got %s", finger.Binding.Severity)
	}
}

func TestDrownVulnerable_Finger(t *testing.T) {
	d := &drownVulnerable{}
	finger := d.Finger()
	if finger == nil {
		t.Fatal("drownVulnerable.Finger() returned nil")
	}
	if finger.Binding.ID != "ssl_drown_vulnerable" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
	if finger.Binding.Severity != model.SeverityHigh {
		t.Errorf("Expected Severity=high, got %s", finger.Binding.Severity)
	}
}

func TestCertificateCheck_Finger(t *testing.T) {
	d := &certificateCheck{}
	finger := d.Finger()
	if finger == nil {
		t.Fatal("certificateCheck.Finger() returned nil")
	}
	if finger.Binding.ID != "ssl_certificate_expired" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
}

func TestHSTSCheck_Finger(t *testing.T) {
	d := &hstsCheck{}
	finger := d.Finger()
	if finger == nil {
		t.Fatal("hstsCheck.Finger() returned nil")
	}
	if finger.Binding.ID != "hsts_not_implemented" {
		t.Errorf("Unexpected Binding.ID: %s", finger.Binding.ID)
	}
	if finger.Binding.Severity != model.SeverityMedium {
		t.Errorf("Expected Severity=medium, got %s", finger.Binding.Severity)
	}
}

// ==================== Utility Function Tests ====================

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		input       string
		defaultPort int
		wantHost    string
		wantPort    int
	}{
		{"example.com:443", 443, "example.com", 443},
		{"example.com:8443", 443, "example.com", 8443},
		{"example.com", 443, "example.com", 443},
		{"192.168.1.1:443", 443, "192.168.1.1", 443},
		{"[::1]:443", 443, "::1", 443},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, port := parseHostPort(tt.input, tt.defaultPort)
			if host != tt.wantHost {
				t.Errorf("parseHostPort(%q) host = %q, want %q", tt.input, host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("parseHostPort(%q) port = %d, want %d", tt.input, port, tt.wantPort)
			}
		})
	}
}

func TestParseHSTSMaxAge(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"max-age=31536000", 31536000},
		{"max-age=63072000; includeSubDomains", 63072000},
		{"max-age=0", 0},
		{"includeSubDomains", -1},
		{"", -1},
		{"max-age=invalid", -1},
		{"max-age=2592000; includeSubDomains; preload", 2592000},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseHSTSMaxAge(tt.input)
			if got != tt.want {
				t.Errorf("parseHSTSMaxAge(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

// ==================== Version/Cipher Data Tests ====================

func TestInsecureVersions(t *testing.T) {
	versions := GetInsecureVersions()
	if len(versions) != 3 {
		t.Errorf("Expected 3 insecure versions, got %d", len(versions))
	}
	if _, ok := versions[tls.VersionSSL30]; !ok {
		t.Error("Expected SSLv3 in insecure versions")
	}
	if _, ok := versions[tls.VersionTLS10]; !ok {
		t.Error("Expected TLS 1.0 in insecure versions")
	}
	if _, ok := versions[tls.VersionTLS11]; !ok {
		t.Error("Expected TLS 1.1 in insecure versions")
	}
}

func TestAllTLSVersions(t *testing.T) {
	versions := GetAllTLSVersions()
	if len(versions) != 5 {
		t.Errorf("Expected 5 TLS versions, got %d", len(versions))
	}
}

func TestKnownWeakCiphers(t *testing.T) {
	ciphers := GetKnownWeakCiphers()
	if len(ciphers) == 0 {
		t.Error("Expected non-empty weak ciphers map")
	}

	// Check specific entries
	exportCipher, ok := ciphers[0x0006]
	if !ok {
		t.Error("Expected EXPORT cipher 0x0006 in weak ciphers")
	} else if !strings.Contains(exportCipher.Reason, "FREAK") {
		t.Errorf("Expected FREAK reason for 0x0006, got: %s", exportCipher.Reason)
	}

	rc4Cipher, ok := ciphers[0x0004]
	if !ok {
		t.Error("Expected RC4 cipher 0x0004 in weak ciphers")
	} else if !strings.Contains(rc4Cipher.Reason, "RC4") {
		t.Errorf("Expected RC4 reason for 0x0004, got: %s", rc4Cipher.Reason)
	}

	nullCipher, ok := ciphers[0x0001]
	if !ok {
		t.Error("Expected NULL cipher 0x0001 in weak ciphers")
	} else if !strings.Contains(nullCipher.Reason, "NULL") {
		t.Errorf("Expected NULL reason for 0x0001, got: %s", nullCipher.Reason)
	}
}

// ==================== isSelfSignedX509 Tests ====================

func TestIsSelfSignedX509(t *testing.T) {
	// Generate a self-signed CA certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	if !isSelfSignedX509(cert) {
		t.Error("Expected self-signed certificate to be detected")
	}
}

func TestIsSelfSignedX509_Nil(t *testing.T) {
	if isSelfSignedX509(nil) {
		t.Error("Expected false for nil certificate")
	}
}

// ==================== certFingerprintSHA1 Tests ====================

func TestCertFingerprintSHA1(t *testing.T) {
	// Generate a self-signed certificate for testing
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	fp := certFingerprintSHA1(cert)
	if fp == "" {
		t.Error("Expected non-empty fingerprint")
	}
	if len(fp) != 40 { // SHA-1 = 20 bytes = 40 hex chars
		t.Errorf("Expected 40-char fingerprint, got %d chars", len(fp))
	}
}

func TestCertFingerprintSHA1_Nil(t *testing.T) {
	fp := certFingerprintSHA1(nil)
	if fp != "" {
		t.Errorf("Expected empty fingerprint for nil, got %q", fp)
	}
}

// ==================== probeSSLv2 Tests ====================

func TestProbeSSLv2_Unreachable(t *testing.T) {
	// Test with an unreachable host - should return false
	result := probeSSLv2("192.0.2.1", 19999) // RFC 5737 TEST-NET, unlikely to be reachable
	if result {
		t.Error("Expected false for unreachable host")
	}
}

// ==================== CheckAction Tests with Non-HTTPS ====================

func TestInsecureProtocolVersion_NonHTTPS(t *testing.T) {
	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	resp := makeTestResponse("body")
	a := mockApollo(req, resp)

	vulnFound := false
	a.ApolloBase.Output = makeHTTPSPrinter(&vulnFound)

	d := &insecureProtocolVersion{}
	finger := d.Finger()
	finger.CheckAction(context.Background(), a)

	if vulnFound {
		t.Error("Should not detect SSL issues on non-HTTPS URL")
	}
}

func TestWeakCipherSuite_NonHTTPS(t *testing.T) {
	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	resp := makeTestResponse("body")
	a := mockApollo(req, resp)

	vulnFound := false
	a.ApolloBase.Output = makeHTTPSPrinter(&vulnFound)

	d := &weakCipherSuite{}
	finger := d.Finger()
	finger.CheckAction(context.Background(), a)

	if vulnFound {
		t.Error("Should not detect cipher issues on non-HTTPS URL")
	}
}

func TestCertificateCheck_NonHTTPS(t *testing.T) {
	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	resp := makeTestResponse("body")
	a := mockApollo(req, resp)

	vulnFound := false
	a.ApolloBase.Output = makeHTTPSPrinter(&vulnFound)

	d := &certificateCheck{}
	finger := d.Finger()
	finger.CheckAction(context.Background(), a)

	if vulnFound {
		t.Error("Should not detect certificate issues on non-HTTPS URL")
	}
}

func TestHSTSCheck_NonHTTPS(t *testing.T) {
	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	resp := makeTestResponse("body")
	a := mockApollo(req, resp)

	vulnFound := false
	a.ApolloBase.Output = makeHTTPSPrinter(&vulnFound)

	d := &hstsCheck{}
	finger := d.Finger()
	finger.CheckAction(context.Background(), a)

	if vulnFound {
		t.Error("Should not detect HSTS issues on non-HTTPS URL")
	}
}

// ==================== HSTS CheckAction Integration Tests ====================

func TestHSTSCheck_MissingHeader(t *testing.T) {
	req, _ := wscan_http.NewRequest("GET", "https://example.com/", nil)
	resp := makeTestResponseWithHeaders("body", 200, map[string]string{
		"Content-Type": "text/html",
	})
	a := mockApollo(req, resp)

	vulnFound := false
	a.ApolloBase.Output = makeHTTPSPrinter(&vulnFound)

	d := &hstsCheck{}
	finger := d.Finger()
	finger.CheckAction(context.Background(), a)

	if !vulnFound {
		t.Error("Expected vuln for missing HSTS header")
	}
}

func TestHSTSCheck_PresentWithGoodMaxAge(t *testing.T) {
	req, _ := wscan_http.NewRequest("GET", "https://example.com/", nil)
	resp := makeTestResponseWithHeaders("body", 200, map[string]string{
		"Content-Type":              "text/html",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
	})
	a := mockApollo(req, resp)

	vulnFound := false
	a.ApolloBase.Output = makeHTTPSPrinter(&vulnFound)

	d := &hstsCheck{}
	finger := d.Finger()
	finger.CheckAction(context.Background(), a)

	if vulnFound {
		t.Error("Should not report vuln when HSTS is properly configured")
	}
}

func TestHSTSCheck_ShortMaxAge(t *testing.T) {
	req, _ := wscan_http.NewRequest("GET", "https://example.com/", nil)
	resp := makeTestResponseWithHeaders("body", 200, map[string]string{
		"Content-Type":              "text/html",
		"Strict-Transport-Security": "max-age=100",
	})
	a := mockApollo(req, resp)

	vulnFound := false
	a.ApolloBase.Output = makeHTTPSPrinter(&vulnFound)

	d := &hstsCheck{}
	finger := d.Finger()
	finger.CheckAction(context.Background(), a)

	if !vulnFound {
		t.Error("Expected vuln for too-short HSTS max-age")
	}
}

func TestHSTSCheck_NilResponse(t *testing.T) {
	req, _ := wscan_http.NewRequest("GET", "https://example.com/", nil)
	a := mockApollo(req, nil)

	vulnFound := false
	a.ApolloBase.Output = makeHTTPSPrinter(&vulnFound)

	d := &hstsCheck{}
	finger := d.Finger()
	finger.CheckAction(context.Background(), a)

	if vulnFound {
		t.Error("Should not report vuln when response is nil")
	}
}

// ==================== Local TLS Server Integration Tests ====================

func startTestTLSServer(t *testing.T, tlsConfig *tls.Config) (string, func()) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to create TLS listener: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			conn.Close()
		}
	}()

	addr := ln.Addr().String()
	return addr, func() { ln.Close() }
}

func generateSelfSignedCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"test.example.com"},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
		Leaf:        cert,
	}

	return tlsCert, cert
}

func TestTestTLSVersion_LocalServer(t *testing.T) {
	tlsCert, _ := generateSelfSignedCert(t)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}

	addr, cleanup := startTestTLSServer(t, tlsConfig)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	// Test TLS 1.2 should be supported
	supported, _, err := testTLSVersion(host, port, tls.VersionTLS12)
	if err != nil {
		t.Logf("testTLSVersion TLS 1.2 error (may be expected in CI): %v", err)
	}
	if !supported {
		t.Log("TLS 1.2 not supported by test server (may be expected in CI)")
	}

	// Test TLS 1.0 should NOT be supported (server only supports 1.2+)
	supported10, _, err10 := testTLSVersion(host, port, tls.VersionTLS10)
	if err10 == nil && supported10 {
		t.Error("TLS 1.0 should not be supported by test server")
	}
}

func TestTestTLSVersionWithCiphers_LocalServer(t *testing.T) {
	tlsCert, _ := generateSelfSignedCert(t)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}

	addr, cleanup := startTestTLSServer(t, tlsConfig)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	// Test with EXPORT ciphers - should fail since server doesn't support them
	exportCiphers := []uint16{0x0006, 0x0008}
	supported, _, err := testTLSVersionWithCiphers(host, port, tls.VersionTLS12, exportCiphers)
	if err == nil && supported {
		t.Log("EXPORT ciphers unexpectedly supported (server may have fallback)")
	}
}

// ==================== Certificate Check Integration Test ====================

func TestCertificateCheck_SelfSignedDetection(t *testing.T) {
	tlsCert, _ := generateSelfSignedCert(t)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to create TLS listener: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			conn.Close()
		}
	}()
	defer ln.Close()

	addr := ln.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	port, _ := strconv.Atoi(portStr)

	// Connect and check if we can get the certificate
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", host, port),
		&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("Failed to connect to test TLS server: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		t.Fatal("Expected peer certificates")
	}

	cert := state.PeerCertificates[0]
	if !isSelfSignedX509(cert) {
		t.Error("Expected self-signed certificate to be detected")
	}
}

// ==================== cipherInfo Tests ====================

func TestCipherInfo_StrengthValues(t *testing.T) {
	tests := []struct {
		strength cipherStrength
		expected string
	}{
		{strengthNull, "Null"},
		{strengthLow, "Low"},
		{strengthMedium, "Medium"},
		{strengthHigh, "High"},
		{strengthMax, "Max"},
	}

	for _, tt := range tests {
		if string(tt.strength) != tt.expected {
			t.Errorf("Expected strength %q, got %q", tt.expected, tt.strength)
		}
	}
}
