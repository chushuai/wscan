/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package flaskaudit

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// Config holds the Flask audit plugin configuration.
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	CheckDebugMode        bool `json:"check_debug_mode" yaml:"check_debug_mode" #:"检测Flask DEBUG模式"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// FlaskAudit is the plugin struct for Flask security audit.
type FlaskAudit struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Close shuts down the plugin.
func (*FlaskAudit) Close() error { return nil }

// DefaultConfig returns the default plugin configuration.
func (*FlaskAudit) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "flask-audit",
			Enabled: true,
		},
		CheckDebugMode: true,
	}
}

// GetConfig returns the current plugin configuration.
func (p *FlaskAudit) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin.
func (p *FlaskAudit) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("FlaskAudit init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// Fingers returns the detection rules for Flask audit.
func (p *FlaskAudit) Fingers() []*base.Finger {
	cfg, ok := p.GetConfig().(*Config)
	if !ok || cfg == nil {
		return nil
	}
	fingers := []*base.Finger{}

	// Flask fingerprint detection — always registered
	fingers = append(fingers, (&flaskFingerprint{}).Finger())

	if cfg.CheckDebugMode {
		fingers = append(fingers, (&flaskDebugMode{}).Finger())
	}

	return fingers
}

// ============================================================================
// Helper functions
// ============================================================================

// isFlaskDetected checks if the target appears to be a Flask application.
func isFlaskDetected(flow *http.Flow) bool {
	if flow == nil || flow.Response == nil {
		return false
	}

	// Check Server header for Werkzeug
	server := flow.Response.Header.Get("Server")
	if strings.Contains(server, "Werkzeug") || strings.Contains(server, "werkzeug") {
		return true
	}

	// Check for Flask session cookie name
	cookies := flow.Response.Cookies()
	for _, cookie := range cookies {
		// Flask default session cookie name
		if cookie.Name == "session" {
			// Flask session cookies are base64-encoded with dots as separators
			if strings.Count(cookie.Value, ".") == 2 {
				return true
			}
		}
	}

	// Check response body for Flask indicators
	body := flow.Response.Text
	if strings.Contains(body, "Flask") ||
		strings.Contains(body, "Werkzeug") ||
		strings.Contains(body, "werkzeug") ||
		strings.Contains(body, "jinja2") ||
		strings.Contains(body, "__debugger__") {
		return true
	}

	return false
}

// resolveURL joins a base URL with a relative path.
func resolveURL(baseURL *url.URL, relativePath string) string {
	u, err := baseURL.Parse(relativePath)
	if err != nil {
		return ""
	}
	return u.String()
}

// extractWerkzeugVersion extracts the Werkzeug version from the Server header.
func extractWerkzeugVersion(serverHeader string) string {
	// Server header format: "Werkzeug/2.0.2 Python/3.9.7" or "Werkzeug/1.0.1"
	re := regexp.MustCompile(`Werkzeug/(\d+\.\d+[\.\d]*)`)
	matches := re.FindStringSubmatch(serverHeader)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ============================================================================
// Flask Fingerprint Detection
// ============================================================================

type flaskFingerprint struct{}

func (*flaskFingerprint) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("flaskaudit/fingerprint: checking %s", flow.Request.URL())

			if isFlaskDetected(flow) {
				a.Set("flask_detected", true)

				// Extract Werkzeug version from Server header
				server := flow.Response.Header.Get("Server")
				version := extractWerkzeugVersion(server)
				if version != "" {
					a.Set("werkzeug_version", version)
					logger.Infof("Flask/Werkzeug detected at %s, version: %s", flow.Request.URL(), version)

					// Map known CVEs
					cves := mapWerkzeugVersionToCVEs(version)
					if len(cves) > 0 {
						a.Set("werkzeug_known_cves", cves)
						logger.Infof("Werkzeug version %s has known CVEs: %v", version, cves)
					}
				} else {
					logger.Infof("Flask/Werkzeug detected at %s", flow.Request.URL())
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "flask-audit/fingerprint",
			Plugin:   "flask-audit/fingerprint",
			Category: "flask-audit/fingerprint",
			Severity: model.SeverityInfo,
		},
	}
}

// mapWerkzeugVersionToCVEs maps a Werkzeug version to known security advisories.
func mapWerkzeugVersionToCVEs(version string) []string {
	if version == "" {
		return nil
	}
	var cves []string

	// Werkzeug < 0.14.1: debug console PIN bypass
	if strings.HasPrefix(version, "0.") {
		parts := strings.Split(version, ".")
		if len(parts) >= 2 {
			minor := parts[1]
			if minor < "14" {
				cves = append(cves, "CVE-2019-14322")
			} else if minor == "14" {
				if len(parts) >= 3 && parts[2] < "1" {
					cves = append(cves, "CVE-2019-14322")
				}
			}
		}
	}

	// Werkzeug < 0.15.3: CVE-2019-14806
	if strings.HasPrefix(version, "0.") {
		parts := strings.Split(version, ".")
		if len(parts) >= 2 {
			minor := parts[1]
			if minor < "15" {
				cves = append(cves, "CVE-2019-14806")
			} else if minor == "15" {
				if len(parts) >= 3 && parts[2] < "3" {
					cves = append(cves, "CVE-2019-14806")
				}
			}
		}
	}

	// Werkzeug < 2.0.1: CVE-2022-29361 (possible but less critical)
	if strings.HasPrefix(version, "1.") {
		cves = append(cves, "CVE-2022-29361")
	}

	return cves
}

// ============================================================================
// Flask Debug Mode Detection
// ============================================================================

type flaskDebugMode struct{}

func (*flaskDebugMode) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("flaskaudit/debug-mode: checking %s", flow.Request.URL())

			if !isFlaskDetected(flow) {
				return nil
			}

			baseURL := flow.Request.URL()

			// Request the Werkzeug debugger JavaScript resource
			// This endpoint is only accessible when Flask is running in debug mode
			debuggerURL := resolveURL(baseURL, "/?__debugger__=yes&cmd=resource&f=debugger.js")

			req, err := http.NewRequest("GET", debuggerURL, nil)
			if err != nil {
				return nil
			}

			resp, err := a.HTTPClient.Respond(context.Background(), req)
			if err != nil || resp == nil {
				return nil
			}

			// Check for Flask debugger signatures
			body := resp.Text
			isDebug := false

			if resp.StatusCode == 200 {
				debugSignatures := []string{
					"if we are in console mode, show the console",
					"werkzeug.debug.console",
					"Werkzeug Debugger",
					"__debugger__",
					"SECRET_KEY",
					"PIN",
				}

				for _, sig := range debugSignatures {
					if strings.Contains(body, sig) {
						isDebug = true
						break
					}
				}
			}

			if isDebug {
				// Extract Werkzeug version from Server header if available
				server := resp.Header.Get("Server")
				version := extractWerkzeugVersion(server)

				v := a.NewWebVuln(req, resp, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "Flask/Werkzeug DEBUG mode is enabled - debugger console is accessible"
					v.Add("framework", "flask")
					v.Add("vuln_type", "debug_console_exposure")
					v.Add("debug_mode", "true")
					if version != "" {
						v.Add("werkzeug_version", version)
					}
					v.Add("cve", "CVE-2019-14322")
					a.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "flask-audit/debug-mode",
			Plugin:   "flask-audit/debug-mode",
			Category: "flask-audit/debug-mode",
			Severity: model.SeverityHigh,
		},
	}
}
