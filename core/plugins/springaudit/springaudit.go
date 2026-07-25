/**
* @Author: wscan middleware audit
* @Description: Spring Boot Audit Plugin - detects Spring Boot fingerprint,
* actuator endpoint exposure, SpEL injection, and known CVEs
 */
package springaudit

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

// isSpringBootApp checks if the target appears to be a Spring Boot application
func isSpringBootApp(flow *http.Flow) bool {
	if flow == nil || flow.Response == nil {
		return false
	}
	// Check X-Application-Context header (Spring Boot specific)
	if flow.Response.GetHeader("X-Application-Context") != "" {
		return true
	}
	// Check for Whitelabel Error Page
	if strings.Contains(flow.Response.Text, "Whitelabel Error Page") {
		return true
	}
	// Check for Spring Boot error page JSON
	if strings.Contains(flow.Response.Text, `"status":`) &&
		strings.Contains(flow.Response.Text, `"error":`) &&
		strings.Contains(flow.Response.Text, `"path":`) {
		return true
	}
	// Check for Spring Framework indicators in headers
	serverHeader := flow.Response.GetHeader("Server")
	if strings.Contains(serverHeader, "Spring") {
		return true
	}
	// Check for common Spring error page patterns
	if strings.Contains(flow.Response.Text, "org.springframework.") ||
		strings.Contains(flow.Response.Text, "spring-boot") {
		return true
	}
	return false
}

// SpringFingerprint detects Spring Boot via error pages and headers
type SpringFingerprint struct{}

func (*SpringFingerprint) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("SpringAudit: fingerprint check for %s", flow.Request.URL().String())

			detected := isSpringBootApp(flow)
			if !detected {
				// Try triggering an error page
				baseURL := flow.Request.URL()
				testURL := http.UrlJoinPath(baseURL.String(), fmt.Sprintf("/%d", utils.RandInt(100000, 999999)))
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					return nil
				}
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					return nil
				}
				if res.GetHeader("X-Application-Context") == "" &&
					!strings.Contains(res.Text, "Whitelabel Error Page") &&
					!strings.Contains(res.Text, "org.springframework.") {
					return nil
				}
				detected = true
			}

			if detected {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "Spring Boot fingerprint detected"
					appCtx := flow.Response.GetHeader("X-Application-Context")
					if appCtx != "" {
						v.Add("x-application-context", appCtx)
					}
					a.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "spring-audit/fingerprint",
			Plugin:   "spring-audit",
			Category: "spring-audit/fingerprint",
			Severity: model.SeverityInfo,
		},
	}
}

// SpringActuatorEndpoints checks for exposed Spring Boot Actuator endpoints
type SpringActuatorEndpoints struct{}

func (*SpringActuatorEndpoints) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("SpringAudit: actuator endpoints check for %s", flow.Request.URL().String())

			baseURL := flow.Request.URL()

			// Actuator v2 paths (Spring Boot 2.x+)
			actuatorV2Paths := []struct {
				path        string
				description string
				severity    model.SeverityLevel
			}{
				{"/actuator", "Actuator root endpoint", model.SeverityLow},
				{"/actuator/env", "Environment properties (may contain secrets)", model.SeverityHigh},
				{"/actuator/health", "Health check information", model.SeverityInfo},
				{"/actuator/info", "Application info", model.SeverityInfo},
				{"/actuator/beans", "Spring beans list", model.SeverityMedium},
				{"/actuator/mappings", "Request mappings", model.SeverityMedium},
				{"/actuator/configprops", "Configuration properties", model.SeverityMedium},
				{"/actuator/loggers", "Logger configuration", model.SeverityMedium},
				{"/actuator/threaddump", "Thread dump", model.SeverityMedium},
				{"/actuator/heapdump", "Heap dump (sensitive data)", model.SeverityCritical},
				{"/actuator/metrics", "Metrics", model.SeverityLow},
				{"/actuator/scheduledtasks", "Scheduled tasks", model.SeverityMedium},
				{"/actuator/sessions", "Active sessions", model.SeverityMedium},
				{"/actuator/shutdown", "Shutdown endpoint (critical)", model.SeverityCritical},
				{"/actuator/trace", "HTTP trace (v1 compat)", model.SeverityMedium},
				{"/actuator/httptrace", "HTTP trace", model.SeverityMedium},
				{"/actuator/auditevents", "Audit events", model.SeverityMedium},
				{"/actuator/conditions", "Auto-configuration conditions", model.SeverityLow},
				{"/actuator/liquibase", "Liquibase database migrations", model.SeverityLow},
				{"/actuator/flyway", "Flyway database migrations", model.SeverityLow},
				{"/actuator/integrationgraph", "Spring Integration graph", model.SeverityLow},
				{"/actuator/caches", "Available caches", model.SeverityLow},
				{"/actuator/logfile", "Log file contents", model.SeverityHigh},
				{"/actuator/prometheus", "Prometheus metrics", model.SeverityLow},
				{"/actuator/startup", "Application startup steps", model.SeverityLow},
				{"/actuator/quartz", "Quartz scheduler jobs", model.SeverityMedium},
			}

			// Actuator v1 paths (Spring Boot 1.x)
			actuatorV1Paths := []struct {
				path        string
				description string
				severity    model.SeverityLevel
			}{
				{"/env", "Environment properties (v1)", model.SeverityHigh},
				{"/health", "Health check (v1)", model.SeverityInfo},
				{"/info", "Application info (v1)", model.SeverityInfo},
				{"/beans", "Spring beans (v1)", model.SeverityMedium},
				{"/mappings", "Request mappings (v1)", model.SeverityMedium},
				{"/configprops", "Configuration properties (v1)", model.SeverityMedium},
				{"/metrics", "Metrics (v1)", model.SeverityLow},
				{"/trace", "HTTP trace (v1)", model.SeverityMedium},
				{"/dump", "Thread dump (v1)", model.SeverityMedium},
				{"/loggers", "Logger config (v1)", model.SeverityMedium},
				{"/auditevents", "Audit events (v1)", model.SeverityMedium},
				{"/autoconfig", "Auto-configuration (v1)", model.SeverityLow},
				{"/jolokia", "Jolokia JMX-HTTP bridge (v1, RCE risk)", model.SeverityCritical},
			}

			allPaths := append(actuatorV2Paths, actuatorV1Paths...)

			for _, p := range allPaths {
				testURL := http.UrlJoinPath(baseURL.String(), p.path)
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					continue
				}
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}
				if res.StatusCode == 200 {
					// Verify it's actually an actuator response, not a SPA catch-all
					contentType := res.GetHeader("Content-Type")
					isActuatorResponse := strings.Contains(contentType, "application/json") ||
						strings.Contains(contentType, "application/vnd.spring-boot.actuator") ||
						strings.Contains(contentType, "text/plain") ||
						strings.Contains(contentType, "application/octet-stream")

					// For heapdump, also check content-disposition
					if strings.Contains(p.path, "heapdump") && res.StatusCode == 200 {
						isActuatorResponse = true
					}

					if isActuatorResponse {
						v := a.NewWebVuln(req, res, nil)
						if v != nil {
							v.SetTargetURL(req.URL())
							v.Payload = p.path + " - " + p.description + " exposed"
							v.Add("path", p.path)
							v.Add("description", p.description)
							a.OutputVuln(v)
						}
					}
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "spring-audit/actuator-endpoints",
			Plugin:   "spring-audit",
			Category: "spring-audit/actuator-endpoints",
			Severity: model.SeverityMedium,
		},
	}
}

// SpringSpELInjection checks for SpEL injection via Whitelabel Error Page
type SpringSpELInjection struct{}

func (*SpringSpELInjection) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("SpringAudit: SpEL injection check for %s", flow.Request.URL().String())

			baseURL := flow.Request.URL()

			// First, verify Whitelabel Error Page is present
			testURL := http.UrlJoinPath(baseURL.String(), fmt.Sprintf("/%d", utils.RandInt(100000, 999999)))
			req, err := http.NewRequest("GET", testURL, nil)
			if err != nil {
				return nil
			}
			res, err := a.HTTPClient.Respond(ctx, req)
			if err != nil {
				return nil
			}
			if !strings.Contains(res.Text, "Whitelabel Error Page") {
				return nil
			}

			// Test SpEL injection via error path parameter
			// CVE-2016-4977 style: ${T(java.lang.Runtime).getRuntime().exec('cmd')}
			// Safe test: ${7*7} should evaluate to 49 if SpEL is injectable
			spelPayloads := []struct {
				payload   string
				indicator string
				cve       string
				desc      string
			}{
				{"${7*7}", "49", "SpEL-Injection", "SpEL injection via error page (arithmetic test)"},
				{"${T(java.lang.Math).random()}", "", "SpEL-Injection", "SpEL injection via Math.random()"},
				{"${T(java.lang.Runtime).getRuntime()}", "java.lang.Runtime", "CVE-2016-4977", "Spring OAuth2 SpEL RCE"},
			}

			for _, sp := range spelPayloads {
				spelURL := http.UrlJoinPath(baseURL.String(), sp.payload)
				spelReq, err := http.NewRequest("GET", spelURL, nil)
				if err != nil {
					continue
				}
				spelRes, err := a.HTTPClient.Respond(ctx, spelReq)
				if err != nil {
					continue
				}
				// Check if SpEL expression was evaluated
				if sp.indicator != "" && strings.Contains(spelRes.Text, sp.indicator) {
					v := a.NewWebVuln(spelReq, spelRes, nil)
					if v != nil {
						v.SetTargetURL(spelReq.URL())
						v.Payload = sp.desc + ": " + sp.payload
						v.Add("cve", sp.cve)
						v.Add("payload", sp.payload)
						a.OutputVuln(v)
					}
					return nil
				}
				// For Runtime test, check if the class reference appears in the response
				if sp.cve == "CVE-2016-4977" && strings.Contains(spelRes.Text, "Runtime") &&
					!strings.Contains(res.Text, "Runtime") {
					v := a.NewWebVuln(spelReq, spelRes, nil)
					if v != nil {
						v.SetTargetURL(spelReq.URL())
						v.Payload = sp.desc
						v.Add("cve", sp.cve)
						v.Add("payload", sp.payload)
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "spring-audit/spel-injection",
			Plugin:   "spring-audit",
			Category: "spring-audit/spel-injection",
			Severity: model.SeverityCritical,
		},
	}
}

// SpringKnownCVEs checks for known Spring/Spring Boot CVEs
type SpringKnownCVEs struct{}

func (*SpringKnownCVEs) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("SpringAudit: known CVEs check for %s", flow.Request.URL().String())

			baseURL := flow.Request.URL()

			// CVE-2016-5007: Spring Security auth bypass via path traversal
			// Check if path traversal through the application bypasses authentication
			cve20165007Paths := []string{
				"/..;/admin",
				"/..;/manager",
				"/..;/actuator/env",
			}
			for _, path := range cve20165007Paths {
				testURL := http.UrlJoinPath(baseURL.String(), path)
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					continue
				}
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}
				// If we get 200 instead of 401/403, the auth bypass may work
				if res.StatusCode == 200 {
					v := a.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(req.URL())
						v.Payload = "CVE-2016-5007: possible Spring Security auth bypass via path traversal"
						v.Add("cve", "CVE-2016-5007")
						v.Add("description", "Spring Security authorization bypass via path traversal")
						v.Add("path", path)
						a.OutputVuln(v)
					}
					return nil
				}
			}

			// CVE-2018-1271: Spring Framework path traversal
			cve20181271Paths := []string{
				"/..%2f..%2f..%2fetc/passwd",
				"/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
			}
			for _, path := range cve20181271Paths {
				testURL := http.UrlJoinPath(baseURL.String(), path)
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					continue
				}
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}
				if res.StatusCode == 200 && strings.Contains(res.Text, "root:") {
					v := a.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(req.URL())
						v.Payload = "CVE-2018-1271: Spring Framework path traversal"
						v.Add("cve", "CVE-2018-1271")
						v.Add("description", "Spring Framework directory traversal vulnerability")
						a.OutputVuln(v)
					}
					return nil
				}
			}

			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "spring-audit/known-cves",
			Plugin:   "spring-audit",
			Category: "spring-audit/known-cves",
			Severity: model.SeverityHigh,
		},
	}
}

// SpringJolokia checks for Jolokia JMX-HTTP bridge which can lead to RCE
type SpringJolokia struct{}

func (*SpringJolokia) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("SpringAudit: Jolokia check for %s", flow.Request.URL().String())

			baseURL := flow.Request.URL()
			jolokiaPaths := []string{"/jolokia", "/actuator/jolokia", "/jolokia/list"}

			for _, path := range jolokiaPaths {
				testURL := http.UrlJoinPath(baseURL.String(), path)
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					continue
				}
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}
				if res.StatusCode == 200 {
					// Check for Jolokia response pattern
					if strings.Contains(res.Text, "jolokia") ||
						strings.Contains(res.Text, "\"request\"") && strings.Contains(res.Text, "\"value\"") {
						v := a.NewWebVuln(req, res, nil)
						if v != nil {
							v.SetTargetURL(req.URL())
							v.Payload = path + " - Jolokia JMX-HTTP bridge exposed (RCE risk)"
							v.Add("path", path)
							v.Add("description", "Jolokia JMX-HTTP bridge allows remote code execution via JMX")

							// Check for restricted/safe mode
							re := regexp.MustCompile(`"error_type"|"status"\s*:\s*403`)
							if re.MatchString(res.Text) {
								v.Add("mode", "restricted")
							} else {
								v.Add("mode", "unrestricted")
							}
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
			ID:       "spring-audit/jolokia",
			Plugin:   "spring-audit",
			Category: "spring-audit/jolokia",
			Severity: model.SeverityHigh,
		},
	}
}

// SpringEnvSecrets checks for sensitive data in /actuator/env responses
type SpringEnvSecrets struct{}

func (*SpringEnvSecrets) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("SpringAudit: env secrets check for %s", flow.Request.URL().String())

			baseURL := flow.Request.URL()
			envPaths := []string{"/actuator/env", "/env"}

			sensitiveKeyPatterns := []*regexp.Regexp{
				regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api.key|apikey|access.key|secret.key|private.key|credential|auth.token|jdbc|database)`),
			}

			for _, path := range envPaths {
				testURL := http.UrlJoinPath(baseURL.String(), path)
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					continue
				}
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}
				if res.StatusCode == 200 && strings.Contains(res.GetHeader("Content-Type"), "application/json") {
					var foundSecrets []string
					for _, pattern := range sensitiveKeyPatterns {
						matches := pattern.FindAllString(res.Text, -1)
						foundSecrets = append(foundSecrets, matches...)
					}
					if len(foundSecrets) > 0 {
						v := a.NewWebVuln(req, res, nil)
						if v != nil {
							v.SetTargetURL(req.URL())
							v.Payload = "Sensitive properties exposed in actuator/env endpoint"
							v.AddStringArray("sensitive_keys", foundSecrets)
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
			ID:       "spring-audit/env-secrets",
			Plugin:   "spring-audit",
			Category: "spring-audit/env-secrets",
			Severity: model.SeverityHigh,
		},
	}
}

// Config holds the plugin configuration
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

// BaseConfig returns the base configuration
func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// SpringAudit is the main plugin struct
type SpringAudit struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Close shuts down the plugin
func (*SpringAudit) Close() error {
	return nil
}

// DefaultConfig returns the default configuration
func (*SpringAudit) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "spring-audit",
		Enabled: true,
	}}
	return config
}

// Fingers returns the detection rules
func (p *SpringAudit) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, (&SpringFingerprint{}).Finger())
	fingers = append(fingers, (&SpringActuatorEndpoints{}).Finger())
	fingers = append(fingers, (&SpringSpELInjection{}).Finger())
	fingers = append(fingers, (&SpringKnownCVEs{}).Finger())
	fingers = append(fingers, (&SpringJolokia{}).Finger())
	fingers = append(fingers, (&SpringEnvSecrets{}).Finger())
	return fingers
}

// GetConfig returns the current configuration
func (p *SpringAudit) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin
func (p *SpringAudit) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("SpringAudit Plugin init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}
