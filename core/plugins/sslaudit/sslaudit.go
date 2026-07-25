/**
* @Author: shaochuyu
* @Date: 6/16/2026
* SSL/TLS Security Audit Plugin
* References: AWVS SSL_Audit.script, Clickjacking_X_Frame_Options.script
 */
package sslaudit

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// SSLAudit implements a comprehensive SSL/TLS security audit plugin.
type SSLAudit struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Config holds the plugin configuration with toggles for each audit category.
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	CheckProtocols        bool `json:"check_protocols" yaml:"check_protocols" #:"检测协议版本"`
	CheckCiphers          bool `json:"check_ciphers" yaml:"check_ciphers" #:"检测密码套件"`
	CheckCertificate      bool `json:"check_certificate" yaml:"check_certificate" #:"检测证书"`
	CheckHeaders          bool `json:"check_headers" yaml:"check_headers" #:"检测安全头"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// Close shuts down the plugin.
func (*SSLAudit) Close() error {
	return nil
}

// DefaultConfig returns the default plugin configuration.
func (*SSLAudit) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:       "sslaudit",
			Enabled:    false,
			IsAdvanced: true,
		},
		CheckProtocols:   true,
		CheckCiphers:     true,
		CheckCertificate: true,
		CheckHeaders:     true,
	}
}

// Fingers returns the detection rules based on the current configuration.
func (p *SSLAudit) Fingers() []*base.Finger {
	cfg, ok := p.GetConfig().(*Config)
	if !ok || cfg == nil {
		return nil
	}
	fingers := []*base.Finger{}

	if cfg.CheckProtocols {
		fingers = append(fingers, (&insecureProtocolVersion{}).Finger())
	}
	if cfg.CheckCiphers {
		fingers = append(fingers, (&weakCipherSuite{}).Finger())
		fingers = append(fingers, (&freakVulnerable{}).Finger())
		fingers = append(fingers, (&drownVulnerable{}).Finger())
	}
	if cfg.CheckCertificate {
		fingers = append(fingers, (&certificateCheck{}).Finger())
	}
	if cfg.CheckHeaders {
		fingers = append(fingers, (&hstsCheck{}).Finger())
	}

	return fingers
}

// GetConfig returns the current plugin configuration.
func (p *SSLAudit) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin.
func (p *SSLAudit) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("SSLAudit init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// ======================== Protocol Version Detection ========================

// tlsVersionInfo maps TLS version constants to human-readable names.
var tlsVersionInfo = map[uint16]string{
	tls.VersionSSL30: "SSLv3",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
	tls.VersionTLS12: "TLS 1.2",
	tls.VersionTLS13: "TLS 1.3",
}

// insecureVersions lists TLS/SSL versions considered insecure.
var insecureVersions = map[uint16]string{
	tls.VersionSSL30: "SSLv3",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
}

// insecureProtocolVersion detects insecure SSL/TLS protocol versions.
type insecureProtocolVersion struct{}

func (d *insecureProtocolVersion) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow.Request.URL().Scheme != "https" {
				return nil
			}

			host, port := parseHostPort(flow.Request.URL().Host, 443)
			logger.Debugf("SSLAudit: checking insecure protocol versions for %s:%d", host, port)

			for version, versionName := range insecureVersions {
				supported, _, err := testTLSVersion(host, port, version)
				if err != nil {
					continue
				}
				if supported {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = fmt.Sprintf("Server supports insecure protocol: %s", versionName)
						v.Add("version", versionName)
						if version == tls.VersionSSL30 {
							v.Add("attack", "POODLE")
						}
						a.OutputVuln(v)
					}
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "ssl_insecure_protocol",
			Plugin:   "sslaudit/protocol/insecure-version",
			Category: "sslaudit/protocol/insecure-version",
			Severity: model.SeverityHigh,
		},
	}
}

// ======================== Weak Cipher Suite Detection ========================

// cipherStrength represents the security strength classification of a cipher suite.
type cipherStrength string

const (
	strengthNull   cipherStrength = "Null"
	strengthLow    cipherStrength = "Low"
	strengthMedium cipherStrength = "Medium"
	strengthHigh   cipherStrength = "High"
	strengthMax    cipherStrength = "Max"
)

// cipherInfo describes a cipher suite's security properties.
type cipherInfo struct {
	Name     string
	Strength cipherStrength
	IsWeak   bool
	Reason   string
}

// knownWeakCiphers maps weak cipher suite IDs to their descriptions.
var knownWeakCiphers = map[uint16]cipherInfo{
	// NULL ciphers
	0x0001: {Name: "TLS_RSA_WITH_NULL_MD5", Strength: strengthNull, IsWeak: true, Reason: "NULL encryption"},
	0x0002: {Name: "TLS_RSA_WITH_NULL_SHA", Strength: strengthNull, IsWeak: true, Reason: "NULL encryption"},
	0x003b: {Name: "TLS_RSA_WITH_NULL_SHA256", Strength: strengthNull, IsWeak: true, Reason: "NULL encryption"},

	// EXPORT ciphers (FREAK attack)
	0x0006: {Name: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", Strength: strengthLow, IsWeak: true, Reason: "EXPORT cipher (FREAK)"},
	0x0008: {Name: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", Strength: strengthLow, IsWeak: true, Reason: "EXPORT cipher (FREAK)"},
	0x000a: {Name: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", Strength: strengthLow, IsWeak: true, Reason: "EXPORT cipher (FREAK)"},
	0x0014: {Name: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", Strength: strengthLow, IsWeak: true, Reason: "EXPORT cipher (FREAK)"},
	0x0019: {Name: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", Strength: strengthLow, IsWeak: true, Reason: "EXPORT cipher (FREAK)"},
	0x0026: {Name: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", Strength: strengthLow, IsWeak: true, Reason: "EXPORT cipher (FREAK)"},
	0x0028: {Name: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", Strength: strengthLow, IsWeak: true, Reason: "EXPORT cipher (FREAK)"},

	// RC4 ciphers
	0x0004: {Name: "TLS_RSA_WITH_RC4_128_MD5", Strength: strengthLow, IsWeak: true, Reason: "RC4 cipher"},
	0x0005: {Name: "TLS_RSA_WITH_RC4_128_SHA", Strength: strengthLow, IsWeak: true, Reason: "RC4 cipher"},
	0x0018: {Name: "TLS_DHE_RSA_WITH_RC4_128_SHA", Strength: strengthLow, IsWeak: true, Reason: "RC4 cipher"},
	0x001b: {Name: "TLS_DHE_DSS_WITH_RC4_128_SHA", Strength: strengthLow, IsWeak: true, Reason: "RC4 cipher"},
	0x0034: {Name: "TLS_DH_anon_WITH_RC4_128_MD5", Strength: strengthLow, IsWeak: true, Reason: "RC4 cipher"},

	// DES ciphers
	0x0009: {Name: "TLS_RSA_WITH_DES_CBC_SHA", Strength: strengthLow, IsWeak: true, Reason: "DES cipher (56-bit)"},
	0x0015: {Name: "TLS_DHE_RSA_WITH_DES_CBC_SHA", Strength: strengthLow, IsWeak: true, Reason: "DES cipher (56-bit)"},
	0x001a: {Name: "TLS_DHE_DSS_WITH_DES_CBC_SHA", Strength: strengthLow, IsWeak: true, Reason: "DES cipher (56-bit)"},
	0x0029: {Name: "TLS_DH_anon_WITH_DES_CBC_SHA", Strength: strengthLow, IsWeak: true, Reason: "DES cipher (56-bit)"},
}

// weakCipherSuite detects weak cipher suites supported by the server.
type weakCipherSuite struct{}

func (d *weakCipherSuite) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow.Request.URL().Scheme != "https" {
				return nil
			}

			host, port := parseHostPort(flow.Request.URL().Host, 443)
			logger.Debugf("SSLAudit: checking weak cipher suites for %s:%d", host, port)

			// First check the default negotiated cipher for each version
			weakCiphers := []string{}
			hasFREAK := false
			hasRC4 := false

			// Check TLS 1.2 and TLS 1.0 negotiated ciphers
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS10} {
				supported, cipherID, err := testTLSVersion(host, port, version)
				if err != nil || !supported {
					continue
				}
				if info, ok := knownWeakCiphers[cipherID]; ok && info.IsWeak {
					weakCiphers = append(weakCiphers, fmt.Sprintf("%s (%s via %s)", info.Name, info.Reason, tlsVersionInfo[version]))
					if strings.Contains(info.Reason, "FREAK") {
						hasFREAK = true
					}
					if strings.Contains(info.Reason, "RC4") {
						hasRC4 = true
					}
				}
			}

			// Additionally, probe individual weak cipher families
			// Group ciphers by type for efficient testing
			exportCipherIDs := []uint16{}
			rc4CipherIDs := []uint16{}
			for id, info := range knownWeakCiphers {
				if strings.Contains(info.Reason, "FREAK") {
					exportCipherIDs = append(exportCipherIDs, id)
				} else if strings.Contains(info.Reason, "RC4") {
					rc4CipherIDs = append(rc4CipherIDs, id)
				}
			}

			// Test EXPORT ciphers (FREAK)
			if !hasFREAK && len(exportCipherIDs) > 0 {
				for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10} {
					ok, cipher, err := testTLSVersionWithCiphers(host, port, version, exportCipherIDs)
					if err != nil || !ok {
						continue
					}
					if info, found := knownWeakCiphers[cipher]; found {
						hasFREAK = true
						weakCiphers = append(weakCiphers, fmt.Sprintf("%s (EXPORT via %s)", info.Name, tlsVersionInfo[version]))
					}
					break
				}
			}

			// Test RC4 ciphers
			if !hasRC4 && len(rc4CipherIDs) > 0 {
				for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10} {
					ok, cipher, err := testTLSVersionWithCiphers(host, port, version, rc4CipherIDs)
					if err != nil || !ok {
						continue
					}
					if info, found := knownWeakCiphers[cipher]; found {
						hasRC4 = true
						weakCiphers = append(weakCiphers, fmt.Sprintf("%s (RC4 via %s)", info.Name, tlsVersionInfo[version]))
					}
					break
				}
			}

			if len(weakCiphers) > 0 {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = fmt.Sprintf("Server supports weak cipher suites: %s", strings.Join(weakCiphers, ", "))
					v.Add("weak_ciphers", strings.Join(weakCiphers, ", "))
					if hasFREAK {
						v.Add("freak_vulnerable", "true")
					}
					if hasRC4 {
						v.Add("rc4_supported", "true")
					}
					a.OutputVuln(v)
				}
			}

			// Report FREAK as separate finding if EXPORT ciphers found
			if hasFREAK {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "Server is vulnerable to FREAK attack (EXPORT cipher suites supported)"
					v.Add("attack", "FREAK")
					a.OutputVuln(v)
				}
			}

			// Report RC4 as separate finding
			if hasRC4 {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "Server supports RC4 cipher suites"
					v.Add("attack", "RC4")
					a.OutputVuln(v)
				}
			}

			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "ssl_weak_cipher",
			Plugin:   "sslaudit/cipher/weak-cipher",
			Category: "sslaudit/cipher/weak-cipher",
			Severity: model.SeverityHigh,
		},
	}
}

// freakVulnerable detects the FREAK attack vulnerability.
type freakVulnerable struct{}

func (d *freakVulnerable) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow.Request.URL().Scheme != "https" {
				return nil
			}

			host, port := parseHostPort(flow.Request.URL().Host, 443)
			logger.Debugf("SSLAudit: checking FREAK vulnerability for %s:%d", host, port)

			exportCipherIDs := []uint16{0x0006, 0x0008, 0x000a, 0x0014, 0x0019, 0x0026, 0x0028}
			supportedVersions := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12}

			for _, version := range supportedVersions {
				ok, _, err := testTLSVersionWithCiphers(host, port, version, exportCipherIDs)
				if err != nil || !ok {
					continue
				}
				// Connection succeeded with EXPORT ciphers
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "Server is vulnerable to FREAK attack: EXPORT cipher suite accepted"
					v.Add("attack", "FREAK")
					v.Add("version", tlsVersionInfo[version])
					a.OutputVuln(v)
				}
				return nil
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "ssl_freak_vulnerable",
			Plugin:   "sslaudit/attack/freak",
			Category: "sslaudit/attack/freak",
			Severity: model.SeverityHigh,
		},
	}
}

// drownVulnerable detects the DROWN attack vulnerability via SSLv2 support.
type drownVulnerable struct{}

func (d *drownVulnerable) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow.Request.URL().Scheme != "https" {
				return nil
			}

			host, port := parseHostPort(flow.Request.URL().Host, 443)
			logger.Debugf("SSLAudit: checking DROWN vulnerability for %s:%d", host, port)

			// DROWN requires SSLv2 support; Go's crypto/tls does not support
			// SSLv2, so we do a raw protocol probe.
			if probeSSLv2(host, port) {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "Server is vulnerable to DROWN attack: SSLv2 is supported"
					v.Add("attack", "DROWN")
					a.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "ssl_drown_vulnerable",
			Plugin:   "sslaudit/attack/drown",
			Category: "sslaudit/attack/drown",
			Severity: model.SeverityHigh,
		},
	}
}

// ======================== Certificate Checks ========================

// certificateCheck performs certificate validity and trust audits.
type certificateCheck struct{}

func (d *certificateCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow.Request.URL().Scheme != "https" {
				return nil
			}

			host, port := parseHostPort(flow.Request.URL().Host, 443)
			logger.Debugf("SSLAudit: checking certificate for %s:%d", host, port)

			dialer := &net.Dialer{Timeout: 5 * time.Second}
			conn, err := tls.DialWithDialer(
				dialer, "tcp", fmt.Sprintf("%s:%d", host, port),
				&tls.Config{InsecureSkipVerify: true},
			)
			if err != nil {
				logger.Debugf("SSLAudit: TLS dial failed for %s:%d: %v", host, port, err)
				return nil
			}
			defer conn.Close()

			state := conn.ConnectionState()
			if len(state.PeerCertificates) == 0 {
				return nil
			}

			cert := state.PeerCertificates[0]
			now := time.Now()
			urlHost := flow.Request.URL().Hostname()

			// Check certificate expiration
			if now.After(cert.NotAfter) {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format(time.RFC3339))
					v.Add("issue", "expired")
					v.Add("not_after", cert.NotAfter.Format(time.RFC3339))
					a.OutputVuln(v)
				}
			}

			// Check certificate expiring within 30 days
			daysUntilExpiry := cert.NotAfter.Sub(now).Hours() / 24
			if daysUntilExpiry > 0 && daysUntilExpiry <= 30 {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = fmt.Sprintf("Certificate expires in %.0f days (%s)", daysUntilExpiry, cert.NotAfter.Format(time.RFC3339))
					v.Add("issue", "expiring_soon")
					v.Add("days_until_expiry", fmt.Sprintf("%.0f", daysUntilExpiry))
					v.Add("not_after", cert.NotAfter.Format(time.RFC3339))
					a.OutputVuln(v)
				}
			}

			// Check self-signed certificate
			if isSelfSignedX509(cert) {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "Certificate is self-signed"
					v.Add("issue", "self_signed")
					v.Add("subject", cert.Subject.CommonName)
					v.Add("fingerprint", certFingerprintSHA1(cert))
					a.OutputVuln(v)
				}
			}

			// Check CN/hostname mismatch
			if err := cert.VerifyHostname(urlHost); err != nil {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = fmt.Sprintf("Certificate CN mismatch: cert CN=%s, expected host=%s", cert.Subject.CommonName, urlHost)
					v.Add("issue", "hostname_mismatch")
					v.Add("cert_cn", cert.Subject.CommonName)
					v.Add("expected_host", urlHost)
					a.OutputVuln(v)
				}
			}

			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "ssl_certificate_expired",
			Plugin:   "sslaudit/certificate/issue",
			Category: "sslaudit/certificate/issue",
			Severity: model.SeverityHigh,
		},
	}
}

// ======================== HSTS Check ========================

// hstsCheck detects missing or misconfigured Strict-Transport-Security header.
type hstsCheck struct{}

func (d *hstsCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow.Request.URL().Scheme != "https" {
				return nil
			}

			logger.Debugf("SSLAudit: checking HSTS header for %s", flow.Request.URL().String())

			if flow.Response == nil {
				return nil
			}

			hstsHeader := flow.Response.GetHeader("Strict-Transport-Security")
			if hstsHeader == "" {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "Strict-Transport-Security (HSTS) header is not implemented"
					v.Add("issue", "hsts_missing")
					a.OutputVuln(v)
				}
				return nil
			}

			// Parse max-age value
			maxAge := parseHSTSMaxAge(hstsHeader)
			if maxAge >= 0 && maxAge < 2592000 { // 30 days = 2592000 seconds
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = fmt.Sprintf("HSTS max-age value is too small: %d seconds (recommended: >= 2592000)", maxAge)
					v.Add("issue", "hsts_short_maxage")
					v.Add("max_age", strconv.Itoa(maxAge))
					a.OutputVuln(v)
				}
			}

			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "hsts_not_implemented",
			Plugin:   "sslaudit/header/hsts",
			Category: "sslaudit/header/hsts",
			Severity: model.SeverityMedium,
		},
	}
}

// ======================== Utility Functions ========================

// parseHostPort splits a host:port string and returns the host and port.
// If no port is present, defaultPort is used.
func parseHostPort(hostPort string, defaultPort int) (string, int) {
	host, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort, defaultPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, defaultPort
	}
	return host, port
}

// testTLSVersion attempts a TLS handshake with a specific protocol version.
// Returns whether the version is supported, the negotiated cipher suite, and any error.
func testTLSVersion(host string, port int, version uint16) (supported bool, cipherSuite uint16, err error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(
		dialer, "tcp", fmt.Sprintf("%s:%d", host, port),
		&tls.Config{
			MinVersion:         version,
			MaxVersion:         version,
			InsecureSkipVerify: true,
		},
	)
	if err != nil {
		return false, 0, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	return true, state.CipherSuite, nil
}

// testTLSVersionWithCiphers tests a specific TLS version with a restricted set of cipher suites.
// Returns whether the connection succeeded, the server-selected cipher suite, and any error.
func testTLSVersionWithCiphers(host string, port int, version uint16, cipherIDs []uint16) (supported bool, cipherSuite uint16, err error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(
		dialer, "tcp", fmt.Sprintf("%s:%d", host, port),
		&tls.Config{
			MinVersion:         version,
			MaxVersion:         version,
			CipherSuites:       cipherIDs,
			InsecureSkipVerify: true,
		},
	)
	if err != nil {
		return false, 0, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	return true, state.CipherSuite, nil
}

// isSelfSignedX509 checks if an x509 certificate is self-signed.
// A certificate is considered self-signed if the issuer matches the subject
// and the certificate can be verified with its own public key.
func isSelfSignedX509(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	// Check if Subject and Issuer are equal by comparing their DER encodings
	if !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return false
	}
	// Verify the signature with the certificate's own public key
	if err := cert.CheckSignatureFrom(cert); err != nil {
		return false
	}
	return true
}

// certFingerprintSHA1 computes the SHA-1 fingerprint of a certificate.
func certFingerprintSHA1(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	return fmt.Sprintf("%X", sha1.Sum(cert.Raw))
}

// probeSSLv2 attempts a raw SSLv2 ClientHello probe.
// Go's crypto/tls does not support SSLv2, so we probe at the byte level.
func probeSSLv2(host string, port int) bool {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return false
	}
	defer conn.Close()

	// SSLv2 ClientHello: message type 0x01, version SSLv2 = 0x0002
	// Format: [length_high | 0x80] [length_low] [0x01] [0x00] [0x02] [cipher_spec_len] [session_id_len] [challenge_len] ...
	// Minimal SSLv2 ClientHello
	clientHello := []byte{
		0x80, 0x26, // length = 38 (0x26)
		0x01,       // message type: ClientHello
		0x00, 0x02, // version: SSLv2
		0x00, 0x18, // cipher_spec_len: 24 (3 cipher specs, 3 bytes each)
		0x00, 0x00, // session_id_len: 0
		0x00, 0x10, // challenge_len: 16
		// Cipher specs (3 bytes each): SSLv2 format
		0x00, 0x00, 0x01, // SSL_RSA_WITH_NULL_MD5
		0x00, 0x02, 0x01, // SSL_RSA_WITH_RC4_128_MD5
		0x00, 0x03, 0x01, // SSL_RSA_WITH_RC2_128_CBC_MD5
		// Challenge (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(clientHello)
	if err != nil {
		return false
	}

	// Read response: SSLv2 ServerHello starts with message type 0x04
	buf := make([]byte, 5)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return false
	}

	// Check if response is an SSLv2 ServerHello
	// SSLv2: first byte has high bit set (no padding), contains length
	// SSLv3/TLS: first byte is 0x15 (alert), 0x16 (handshake), or 0x17 (application)
	if buf[0]&0x80 != 0 && buf[0] != 0x15 && buf[0] != 0x16 && buf[0] != 0x17 {
		return true
	}

	return false
}

// parseHSTSMaxAge extracts the max-age directive value from an HSTS header string.
// Returns -1 if max-age is not found or cannot be parsed.
func parseHSTSMaxAge(hstsValue string) int {
	parts := strings.Split(hstsValue, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "max-age=") {
			valueStr := strings.TrimPrefix(part, "max-age=")
			value, err := strconv.Atoi(valueStr)
			if err != nil {
				return -1
			}
			return value
		}
	}
	return -1
}

// GetAllTLSVersions returns all known TLS version constants for testing.
func GetAllTLSVersions() map[uint16]string {
	return tlsVersionInfo
}

// GetInsecureVersions returns all insecure TLS version constants for testing.
func GetInsecureVersions() map[uint16]string {
	return insecureVersions
}

// GetKnownWeakCiphers returns the map of known weak cipher IDs for testing.
func GetKnownWeakCiphers() map[uint16]cipherInfo {
	return knownWeakCiphers
}
