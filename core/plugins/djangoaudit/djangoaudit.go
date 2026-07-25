/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package djangoaudit

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// Config holds the Django audit plugin configuration.
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	CheckAdminInterface   bool `json:"check_admin_interface" yaml:"check_admin_interface" #:"检测Django管理界面弱口令"`
	CheckDebugMode        bool `json:"check_debug_mode" yaml:"check_debug_mode" #:"检测Django DEBUG模式"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// DjangoAudit is the plugin struct for Django security audit.
type DjangoAudit struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Close shuts down the plugin.
func (*DjangoAudit) Close() error { return nil }

// DefaultConfig returns the default plugin configuration.
func (*DjangoAudit) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "django-audit",
			Enabled: true,
		},
		CheckAdminInterface: true,
		CheckDebugMode:      true,
	}
}

// GetConfig returns the current plugin configuration.
func (p *DjangoAudit) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin.
func (p *DjangoAudit) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("DjangoAudit init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// Fingers returns the detection rules for Django audit.
func (p *DjangoAudit) Fingers() []*base.Finger {
	cfg, ok := p.GetConfig().(*Config)
	if !ok || cfg == nil {
		return nil
	}
	fingers := []*base.Finger{}

	// Django fingerprint detection — always registered
	fingers = append(fingers, (&djangoFingerprint{}).Finger())

	if cfg.CheckAdminInterface {
		fingers = append(fingers, (&djangoAdminWeakPassword{}).Finger())
	}
	if cfg.CheckDebugMode {
		fingers = append(fingers, (&djangoDebugMode{}).Finger())
	}

	return fingers
}

// ============================================================================
// Helper functions
// ============================================================================

// isDjangoDetected checks if the target appears to be a Django application.
func isDjangoDetected(flow *http.Flow) bool {
	if flow == nil || flow.Response == nil {
		return false
	}

	// Check for csrftoken cookie
	cookies := flow.Response.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "csrftoken" {
			return true
		}
	}

	// Check Set-Cookie header for Django patterns
	for _, cookie := range cookies {
		if cookie.Name == "sessionid" || cookie.Name == "django_language" ||
			cookie.Name == "django_timezone" {
			return true
		}
	}

	// Check X-Frame-Options and other Django-typical headers
	xFrame := flow.Response.Header.Get("X-Frame-Options")
	contentType := flow.Response.Header.Get("X-Content-Type-Options")
	if xFrame == "DENY" && contentType == "nosniff" {
		// Common Django security header combination, but not definitive
		// Check further in body
	}

	// Check response body for Django indicators
	body := flow.Response.Text
	if strings.Contains(body, "csrfmiddlewaretoken") ||
		strings.Contains(body, "Django site admin") ||
		strings.Contains(body, "django-admin") ||
		strings.Contains(body, "powered by Django") ||
		strings.Contains(body, "The install worked successfully") {
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

// extractCSRFToken extracts the CSRF token from a Django admin page.
func extractCSRFToken(body string) string {
	// Try to extract from hidden input field
	re := regexp.MustCompile(`name="csrfmiddlewaretoken"\s+value="([^"]+)"`)
	matches := re.FindStringSubmatch(body)
	if len(matches) > 1 {
		return matches[1]
	}

	// Try alternative format
	re2 := regexp.MustCompile(`value="([^"]+)"\s+name="csrfmiddlewaretoken"`)
	matches2 := re2.FindStringSubmatch(body)
	if len(matches2) > 1 {
		return matches2[1]
	}

	return ""
}

// extractCSRFCookie extracts the csrftoken cookie value from response cookies.
func extractCSRFCookie(resp *http.Response) string {
	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "csrftoken" {
			return cookie.Value
		}
	}
	return ""
}

// extractSessionID extracts the sessionid cookie value from response cookies.
func extractSessionID(resp *http.Response) string {
	cookies := resp.Cookies()
	for _, cookie := range cookies {
		if cookie.Name == "sessionid" {
			return cookie.Value
		}
	}
	return ""
}

// ============================================================================
// Django Fingerprint Detection
// ============================================================================

type djangoFingerprint struct{}

func (*djangoFingerprint) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("djangoaudit/fingerprint: checking %s", flow.Request.URL())

			if isDjangoDetected(flow) {
				a.Set("django_detected", true)

				// Extract version info if available
				version := extractDjangoVersion(flow.Response.Text)
				if version != "" {
					a.Set("django_version", version)
					logger.Infof("Django detected at %s, version: %s", flow.Request.URL(), version)
				} else {
					logger.Infof("Django detected at %s", flow.Request.URL())
				}

				// Map known CVEs based on version
				cves := mapDjangoVersionToCVEs(version)
				if len(cves) > 0 {
					a.Set("django_known_cves", cves)
					logger.Infof("Django version %s has known CVEs: %v", version, cves)
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "django-audit/fingerprint",
			Plugin:   "django-audit/fingerprint",
			Category: "django-audit/fingerprint",
			Severity: model.SeverityInfo,
		},
	}
}

// extractDjangoVersion attempts to extract the Django version from page content.
func extractDjangoVersion(body string) string {
	// Django debug pages often contain version info
	patterns := []string{
		`Django Version:\s*(\d+\.\d+[\.\d]*)`,
		`Django/(\d+\.\d+[\.\d]*)`,
		`django[_-]version["\s:=]+(\d+\.\d+[\.\d]*)`,
	}
	for _, pat := range patterns {
		re := regexp.MustCompile(pat)
		matches := re.FindStringSubmatch(body)
		if len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
}

// mapDjangoVersionToCVEs maps a Django version to known security advisories.
func mapDjangoVersionToCVEs(version string) []string {
	if version == "" {
		return nil
	}
	var cves []string

	// Django < 2.2
	if strings.HasPrefix(version, "1.") || strings.HasPrefix(version, "2.0") || strings.HasPrefix(version, "2.1") {
		cves = append(cves, "CVE-2019-6975", "CVE-2019-3496")
	}
	// Django < 3.0
	if strings.HasPrefix(version, "2.2") {
		cves = append(cves, "CVE-2020-9402", "CVE-2020-7471")
	}
	// Django < 3.2
	if strings.HasPrefix(version, "3.0") || strings.HasPrefix(version, "3.1") {
		cves = append(cves, "CVE-2021-31542", "CVE-2021-32052")
	}
	// Django < 4.0
	if strings.HasPrefix(version, "3.2") {
		cves = append(cves, "CVE-2022-28347", "CVE-2022-34265")
	}
	// Django < 4.2
	if strings.HasPrefix(version, "4.0") || strings.HasPrefix(version, "4.1") {
		cves = append(cves, "CVE-2023-46695", "CVE-2023-41164")
	}

	return cves
}

// ============================================================================
// Django Admin Weak Password
// ============================================================================

// djangoCreds contains common Django admin credential pairs.
var djangoCreds = []struct {
	username string
	password string
}{
	{"admin", "admin"},
	{"admin", "admin123"},
	{"admin", "password"},
	{"admin", "123456"},
	{"admin", "root"},
	{"root", "root"},
	{"root", "admin"},
	{"django", "django"},
	{"user", "user"},
	{"admin", "admin1"},
}

type djangoAdminWeakPassword struct{}

func (*djangoAdminWeakPassword) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("djangoaudit/admin-weak-password: checking %s", flow.Request.URL())

			if !isDjangoDetected(flow) {
				return nil
			}

			baseURL := flow.Request.URL()

			// Check /admin/ for Django admin login page
			adminURL := resolveURL(baseURL, "/admin/")
			req, resp, err := doRequest(a, "GET", adminURL, nil, nil)
			if err != nil || resp == nil {
				return nil
			}

			// Verify it's a Django admin login page
			body := resp.Text
			if resp.StatusCode != 200 {
				return nil
			}
			if !strings.Contains(body, "csrfmiddlewaretoken") &&
				!strings.Contains(body, "Django site admin") &&
				!strings.Contains(body, "<title>Log in") {
				return nil
			}

			// Extract CSRF token and cookies
			csrfToken := extractCSRFToken(body)
			csrfCookie := extractCSRFCookie(resp)
			sessionID := extractSessionID(resp)

			if csrfToken == "" && csrfCookie == "" {
				return nil
			}

			// Use the cookie value if the form token is not found
			if csrfToken == "" {
				csrfToken = csrfCookie
			}

			// Test each credential pair with CSRF handling
			loginURL := resolveURL(baseURL, "/admin/login/")
			for _, cred := range djangoCreds {
				formData := fmt.Sprintf(
					"csrfmiddlewaretoken=%s&username=%s&password=%s&next=/admin/",
					csrfToken, cred.username, cred.password,
				)

				headers := map[string]string{
					"Content-Type": "application/x-www-form-urlencoded",
					"Referer":      adminURL,
				}
				if csrfCookie != "" {
					cookieHeader := fmt.Sprintf("csrftoken=%s", csrfCookie)
					if sessionID != "" {
						cookieHeader += fmt.Sprintf("; sessionid=%s", sessionID)
					}
					headers["Cookie"] = cookieHeader
				}

				loginReq, loginResp, err := doRequest(a, "POST", loginURL, strings.NewReader(formData), headers)
				if err != nil || loginResp == nil {
					continue
				}

				// Successful login typically results in a 302 redirect
				if loginResp.StatusCode == 302 || loginResp.StatusCode == 301 {
					location := loginResp.Header.Get("Location")
					// If redirect goes to /admin/ or other admin pages (not back to login), success
					if !strings.Contains(location, "login") || strings.Contains(location, "/admin/") {
						v := a.NewWebVuln(loginReq, loginResp, nil)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = fmt.Sprintf("Django admin weak password: %s/%s", cred.username, cred.password)
							v.Add("framework", "django")
							v.Add("username", cred.username)
							v.Add("password", cred.password)
							v.Add("admin_url", adminURL)
							a.OutputVuln(v)
						}
						return nil
					}
				}

				// Also check for successful login indicators in response body
				if loginResp.StatusCode == 200 {
					loginBody := loginResp.Text
					if strings.Contains(loginBody, "Site administration") ||
						strings.Contains(loginBody, "Django site admin") ||
						(strings.Contains(loginBody, "Welcome") && !strings.Contains(loginBody, "error")) {
						v := a.NewWebVuln(loginReq, loginResp, nil)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = fmt.Sprintf("Django admin weak password: %s/%s", cred.username, cred.password)
							v.Add("framework", "django")
							v.Add("username", cred.username)
							v.Add("password", cred.password)
							v.Add("admin_url", adminURL)
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
			ID:       "django-audit/admin-weak-password",
			Plugin:   "django-audit/admin-weak-password",
			Category: "django-audit/admin-weak-password",
			Severity: model.SeverityCritical,
		},
	}
}

// ============================================================================
// Django Debug Mode Detection
// ============================================================================

type djangoDebugMode struct{}

func (*djangoDebugMode) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("djangoaudit/debug-mode: checking %s", flow.Request.URL())

			if !isDjangoDetected(flow) {
				return nil
			}

			baseURL := flow.Request.URL()

			// Send request with invalid Host header to trigger DisallowedHost debug page
			checkURL := resolveURL(baseURL, "/")
			req, err := http.NewRequest("GET", checkURL, nil)
			if err != nil {
				return nil
			}
			// Set an invalid Host header to trigger DisallowedHost exception
			req.Header.Set("Host", "SomeInvalidHost")

			resp, err := a.HTTPClient.Respond(context.Background(), req)
			if err != nil || resp == nil {
				return nil
			}

			body := resp.Text

			// Check for Django debug page indicators
			isDebug := false
			debugIndicators := []string{
				"DisallowedHost at",
				"DisallowedHost at /",
				"SuspiciousOperation at",
				"Exception Value:",
				"Django Version:",
				"Python Executable:",
				"exception module",
			}

			for _, indicator := range debugIndicators {
				if strings.Contains(body, indicator) {
					isDebug = true
					break
				}
			}

			// Also check for Django debug page HTML structure
			if resp.StatusCode == 400 || resp.StatusCode == 500 {
				if strings.Contains(body, "django") && strings.Contains(body, "Traceback") {
					isDebug = true
				}
			}

			if isDebug {
				// Try to extract version from debug page
				version := extractDjangoVersion(body)

				v := a.NewWebVuln(req, resp, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "Django DEBUG mode is enabled - sensitive information may be exposed"
					v.Add("framework", "django")
					v.Add("vuln_type", "info_exposure")
					v.Add("debug_mode", "true")
					if version != "" {
						v.Add("django_version", version)
					}
					a.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "django-audit/debug-mode",
			Plugin:   "django-audit/debug-mode",
			Category: "django-audit/debug-mode",
			Severity: model.SeverityMedium,
		},
	}
}
