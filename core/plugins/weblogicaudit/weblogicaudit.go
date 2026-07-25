/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package weblogicaudit

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// Config holds the WebLogic audit plugin configuration.
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	CheckDefaultCreds     bool `json:"check_default_creds" yaml:"check_default_creds" #:"检测WebLogic默认凭据"`
	CheckSSRF             bool `json:"check_ssrf" yaml:"check_ssrf" #:"检测UDDI Explorer SSRF漏洞"`
	CheckWLSWSAT          bool `json:"check_wls_wsat" yaml:"check_wls_wsat" #:"检测wls-wsat RCE漏洞"`
	CheckConsoleExposure  bool `json:"check_console_exposure" yaml:"check_console_exposure" #:"检测WebLogic控制台暴露"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// WebLogicAudit is the plugin struct for WebLogic security audit.
type WebLogicAudit struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Close shuts down the plugin.
func (*WebLogicAudit) Close() error { return nil }

// DefaultConfig returns the default plugin configuration.
func (*WebLogicAudit) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "weblogic-audit",
			Enabled: true,
		},
		CheckDefaultCreds:    true,
		CheckSSRF:            true,
		CheckWLSWSAT:         true,
		CheckConsoleExposure: true,
	}
}

// GetConfig returns the current plugin configuration.
func (p *WebLogicAudit) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin.
func (p *WebLogicAudit) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("WebLogicAudit init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// Fingers returns the detection rules for WebLogic audit.
func (p *WebLogicAudit) Fingers() []*base.Finger {
	cfg, ok := p.GetConfig().(*Config)
	if !ok || cfg == nil {
		return nil
	}
	fingers := []*base.Finger{}

	// WebLogic fingerprint detection — always registered
	fingers = append(fingers, (&weblogicFingerprint{}).Finger())

	if cfg.CheckDefaultCreds {
		fingers = append(fingers, (&weblogicDefaultCreds{}).Finger())
	}
	if cfg.CheckSSRF {
		fingers = append(fingers, (&weblogicUDDISSRF{}).Finger())
	}
	if cfg.CheckWLSWSAT {
		fingers = append(fingers, (&weblogicWLSWSATRCE{}).Finger())
	}
	if cfg.CheckConsoleExposure {
		fingers = append(fingers, (&weblogicConsoleExposure{}).Finger())
	}

	return fingers
}

// ============================================================================
// Helper functions
// ============================================================================

// isWebLogicDetected checks if the target appears to be WebLogic based on
// response headers and page content from the initial flow.
func isWebLogicDetected(flow *http.Flow) bool {
	if flow == nil || flow.Response == nil {
		return false
	}

	// Check Server header
	server := flow.Response.Header.Get("Server")
	if strings.Contains(strings.ToLower(server), "weblogic") ||
		strings.Contains(strings.ToLower(server), "bea") ||
		strings.Contains(strings.ToLower(server), "wls") {
		return true
	}

	// Check X-Powered-By header
	xpb := flow.Response.Header.Get("X-Powered-By")
	if strings.Contains(strings.ToLower(xpb), "weblogic") ||
		strings.Contains(strings.ToLower(xpb), "servlet") {
		return true
	}

	// Check response body for WebLogic indicators
	body := flow.Response.Text
	if strings.Contains(body, "WebLogic") ||
		strings.Contains(body, "BEA WebLogic") ||
		strings.Contains(body, "Oracle WebLogic") ||
		strings.Contains(body, "/console/login/LoginForm.jsp") ||
		strings.Contains(body, "WebLogic Server") {
		return true
	}

	return false
}

// doRequest sends an HTTP request and returns the request, response, and error.
func doRequest(apollo *base.Apollo, method, rawURL string, body io.Reader, headers map[string]string) (*http.Request, *http.Response, error) {
	req, err := http.NewRequest(method, rawURL, body)
	if err != nil {
		return nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := apollo.HTTPClient.Respond(context.Background(), req)
	if err != nil {
		return nil, nil, err
	}
	return req, resp, nil
}

// resolveURL joins a base URL with a relative path.
func resolveURL(baseURL *url.URL, relativePath string) string {
	u, err := baseURL.Parse(relativePath)
	if err != nil {
		return ""
	}
	return u.String()
}

// ============================================================================
// WebLogic Fingerprint Detection
// ============================================================================

type weblogicFingerprint struct{}

func (*weblogicFingerprint) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("weblogicaudit/fingerprint: checking %s", flow.Request.URL())

			if isWebLogicDetected(flow) {
				// Store fingerprint result for other checks
				a.Set("weblogic_detected", true)

				// Extract version from Server header
				server := flow.Response.Header.Get("Server")
				version := extractWebLogicVersion(server, flow.Response.Text)
				if version != "" {
					a.Set("weblogic_version", version)
					logger.Infof("WebLogic detected at %s, version: %s", flow.Request.URL(), version)
				} else {
					logger.Infof("WebLogic detected at %s", flow.Request.URL())
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "weblogic-audit/fingerprint",
			Plugin:   "weblogic-audit/fingerprint",
			Category: "weblogic-audit/fingerprint",
			Severity: model.SeverityInfo,
		},
	}
}

// extractWebLogicVersion attempts to extract the WebLogic version from headers or page content.
func extractWebLogicVersion(serverHeader, body string) string {
	// Try Server header: "WebLogic Server 12.2.1.4.0" or similar
	serverLower := strings.ToLower(serverHeader)
	if idx := strings.Index(serverLower, "weblogic"); idx != -1 {
		remainder := serverHeader[idx:]
		parts := strings.Fields(remainder)
		for _, p := range parts[1:] {
			// Check if this looks like a version number
			if strings.Contains(p, ".") && len(p) >= 3 {
				return p
			}
		}
	}

	// Try to extract from body (LoginForm.jsp often contains version)
	// Look for patterns like "WebLogic Server Version: 12.2.1.4.0"
	versionPatterns := []string{
		"WebLogic Server Version:",
		"WebLogic Server ",
		"BEA WebLogic ",
		"Oracle WebLogic Server ",
	}
	for _, pat := range versionPatterns {
		if idx := strings.Index(body, pat); idx != -1 {
			remainder := body[idx+len(pat):]
			remainder = strings.TrimSpace(remainder)
			// Extract version-like string
			var versionChars []byte
			for _, c := range []byte(remainder) {
				if (c >= '0' && c <= '9') || c == '.' {
					versionChars = append(versionChars, c)
				} else {
					break
				}
			}
			if len(versionChars) >= 3 {
				return string(versionChars)
			}
		}
	}

	return ""
}

// ============================================================================
// WebLogic Default Credentials Check
// ============================================================================

// webLogicCreds contains default WebLogic credential pairs.
var webLogicCreds = []struct {
	username string
	password string
}{
	{"weblogic", "weblogic"},
	{"weblogic", "welcome1"},
	{"weblogic", "password"},
	{"weblogic", "weblogic123"},
	{"system", "password"},
	{"system", "weblogic"},
	{"guest", "guest"},
	{"admin", "admin"},
	{"weblogic", "Weblogic1"},
	{"weblogic", "Welcome1"},
}

type weblogicDefaultCreds struct{}

func (*weblogicDefaultCreds) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("weblogicaudit/default-creds: checking %s", flow.Request.URL())

			// First check if WebLogic is detected
			if !isWebLogicDetected(flow) {
				return nil
			}

			baseURL := flow.Request.URL()

			// Check if console login page exists
			consoleURL := resolveURL(baseURL, "/console/login/LoginForm.jsp")
			req, resp, err := doRequest(a, "GET", consoleURL, nil, nil)
			if err != nil || resp == nil {
				return nil
			}

			// Verify it's a WebLogic console page
			if resp.StatusCode != 200 || !strings.Contains(resp.Text, "j_security_check") {
				return nil
			}

			// Test each credential pair
			loginURL := resolveURL(baseURL, "/console/j_security_check")
			for _, cred := range webLogicCreds {
				formData := fmt.Sprintf("j_username=%s&j_password=%s", cred.username, cred.password)
				headers := map[string]string{
					"Content-Type": "application/x-www-form-urlencoded",
				}

				loginReq, loginResp, err := doRequest(a, "POST", loginURL, strings.NewReader(formData), headers)
				if err != nil || loginResp == nil {
					continue
				}

				// Successful login typically results in a 302 redirect
				// Failed login typically results in 401 or returns to login page with error
				if loginResp.StatusCode == 302 || loginResp.StatusCode == 301 {
					location := loginResp.Header.Get("Location")
					// If redirect doesn't go back to login error page, it's a success
					if !strings.Contains(location, "error") && !strings.Contains(location, "Error") && !strings.Contains(location, "login") {
						v := a.NewWebVuln(loginReq, loginResp, nil)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = fmt.Sprintf("Default credentials: %s/%s", cred.username, cred.password)
							v.Add("framework", "weblogic")
							v.Add("username", cred.username)
							v.Add("password", cred.password)
							v.Add("console_url", consoleURL)
							a.OutputVuln(v)
						}
						return nil // Found valid creds, stop testing
					}
				}

				// Also check for successful login indicators in response body
				if loginResp.StatusCode == 200 {
					if strings.Contains(loginResp.Text, "Welcome") ||
						strings.Contains(loginResp.Text, "Administration Console") ||
						strings.Contains(loginResp.Text, "Change Center") {
						v := a.NewWebVuln(loginReq, loginResp, nil)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = fmt.Sprintf("Default credentials: %s/%s", cred.username, cred.password)
							v.Add("framework", "weblogic")
							v.Add("username", cred.username)
							v.Add("password", cred.password)
							v.Add("console_url", consoleURL)
							a.OutputVuln(v)
						}
						return nil
					}
				}
				_ = req // suppress unused variable warning
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "weblogic-audit/default-creds",
			Plugin:   "weblogic-audit/default-creds",
			Category: "weblogic-audit/default-creds",
			Severity: model.SeverityCritical,
		},
	}
}

// ============================================================================
// WebLogic UDDI Explorer SSRF
// ============================================================================

type weblogicUDDISSRF struct{}

func (*weblogicUDDISSRF) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("weblogicaudit/uddi-ssrf: checking %s", flow.Request.URL())

			if !isWebLogicDetected(flow) {
				return nil
			}

			baseURL := flow.Request.URL()

			// Check /uddiexplorer/ endpoint
			uddiPaths := []string{
				"/uddiexplorer/",
				"/uddiexplorer/SearchPublicRegistries.jsp",
			}

			for _, path := range uddiPaths {
				checkURL := resolveURL(baseURL, path)
				req, resp, err := doRequest(a, "GET", checkURL, nil, nil)
				if err != nil || resp == nil {
					continue
				}

				// UDDI explorer accessible
				if resp.StatusCode == 200 {
					body := resp.Text
					if strings.Contains(body, "UDDI Explorer") ||
						strings.Contains(body, "uddiexplorer") ||
						strings.Contains(body, "SearchPublicRegistries") {

						// Check if it's the search page that allows SSRF
						if strings.Contains(body, "SearchPublicRegistries") ||
							strings.Contains(body, "operator") {
							v := a.NewWebVuln(req, resp, nil)
							if v != nil {
								v.SetTargetURL(flow.Request.URL())
								v.Payload = "UDDI Explorer SSRF vulnerability detected"
								v.Add("framework", "weblogic")
								v.Add("endpoint", path)
								v.Add("vuln_type", "ssrf")
								v.Add("cve", "CVE-2014-4210")
								a.OutputVuln(v)
							}
							return nil
						}

						// UDDI explorer exists but may not have the SSRF-vulnerable search page
						v := a.NewWebVuln(req, resp, nil)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = "UDDI Explorer endpoint exposed"
							v.Add("framework", "weblogic")
							v.Add("endpoint", path)
							v.Add("vuln_type", "info_exposure")
							a.OutputVuln(v)
						}
						return nil
					}
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "weblogic-audit/uddi-ssrf",
			Plugin:   "weblogic-audit/uddi-ssrf",
			Category: "weblogic-audit/uddi-ssrf",
			Severity: model.SeverityHigh,
		},
	}
}

// ============================================================================
// WebLogic wls-wsat RCE (CVE-2017-10271, CVE-2019-2725)
// ============================================================================

type weblogicWLSWSATRCE struct{}

func (*weblogicWLSWSATRCE) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("weblogicaudit/wls-wsat-rce: checking %s", flow.Request.URL())

			if !isWebLogicDetected(flow) {
				return nil
			}

			baseURL := flow.Request.URL()

			// Check /wls-wsat/ endpoint for CVE-2017-10271 and CVE-2019-2725
			wlsPaths := []string{
				"/wls-wsat/CoordinatorPortType",
				"/wls-wsat/RegistrationPortTypeRPC",
				"/wls-wsat/ParticipantPortType",
			}

			for _, path := range wlsPaths {
				checkURL := resolveURL(baseURL, path)

				// Send a SOAP request to check if the endpoint is reachable
				soapPayload := `<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing">
<soapenv:Header>
<wsa:Action>http://ws.apache.org/muse/helloworld/HelloWorld/GetResource</wsa:Action>
<wsa:ReplyTo><wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address></wsa:ReplyTo>
</soapenv:Header>
<soapenv:Body/>
</soapenv:Envelope>`

				headers := map[string]string{
					"Content-Type": "text/xml",
					"SOAPAction":   "",
				}

				req, resp, err := doRequest(a, "POST", checkURL, strings.NewReader(soapPayload), headers)
				if err != nil || resp == nil {
					continue
				}

				// If endpoint returns 200 or 500 with SOAP-related content, it's likely vulnerable
				body := resp.Text
				if resp.StatusCode == 200 || resp.StatusCode == 500 {
					if strings.Contains(body, "soap") ||
						strings.Contains(body, "SOAP") ||
						strings.Contains(body, "Envelope") ||
						strings.Contains(body, "wls-wsat") {

						v := a.NewWebVuln(req, resp, nil)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = "wls-wsat endpoint accessible, potentially vulnerable to RCE"
							v.Add("framework", "weblogic")
							v.Add("endpoint", path)
							v.Add("vuln_type", "rce")
							v.Add("cve", "CVE-2017-10271,CVE-2019-2725")
							a.OutputVuln(v)
						}
						return nil
					}
				}
			}

			// Also check /_async/ endpoint for CVE-2019-2725
			asyncPaths := []string{
				"/_async/AsyncResponseService",
				"/_async/AsyncResponseServiceHttps",
			}

			for _, path := range asyncPaths {
				checkURL := resolveURL(baseURL, path)
				req, resp, err := doRequest(a, "GET", checkURL, nil, nil)
				if err != nil || resp == nil {
					continue
				}

				if resp.StatusCode == 200 || resp.StatusCode == 500 {
					v := a.NewWebVuln(req, resp, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "Async endpoint accessible, potentially vulnerable to CVE-2019-2725"
						v.Add("framework", "weblogic")
						v.Add("endpoint", path)
						v.Add("vuln_type", "rce")
						v.Add("cve", "CVE-2019-2725")
						a.OutputVuln(v)
					}
					return nil
				}
			}

			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "weblogic-audit/wls-wsat-rce",
			Plugin:   "weblogic-audit/wls-wsat-rce",
			Category: "weblogic-audit/wls-wsat-rce",
			Severity: model.SeverityCritical,
		},
	}
}

// ============================================================================
// WebLogic Console Exposure
// ============================================================================

type weblogicConsoleExposure struct{}

func (*weblogicConsoleExposure) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("weblogicaudit/console-exposure: checking %s", flow.Request.URL())

			if !isWebLogicDetected(flow) {
				return nil
			}

			baseURL := flow.Request.URL()

			// Check console endpoints
			consolePaths := []string{
				"/console/",
				"/console/login/LoginForm.jsp",
			}

			for _, path := range consolePaths {
				checkURL := resolveURL(baseURL, path)
				req, resp, err := doRequest(a, "GET", checkURL, nil, nil)
				if err != nil || resp == nil {
					continue
				}

				if resp.StatusCode == 200 {
					body := resp.Text
					if strings.Contains(body, "WebLogic") ||
						strings.Contains(body, "BEA WebLogic") ||
						strings.Contains(body, "Oracle WebLogic") ||
						strings.Contains(body, "Administration Console") ||
						strings.Contains(body, "j_security_check") {

						v := a.NewWebVuln(req, resp, nil)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = "WebLogic admin console exposed"
							v.Add("framework", "weblogic")
							v.Add("endpoint", path)
							v.Add("vuln_type", "info_exposure")
							a.OutputVuln(v)
						}
						return nil
					}
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "weblogic-audit/console-exposure",
			Plugin:   "weblogic-audit/console-exposure",
			Category: "weblogic-audit/console-exposure",
			Severity: model.SeverityMedium,
		},
	}
}
