/**
* @Author: wscan middleware audit
* @Description: JBoss Audit Plugin - detects JBoss fingerprint, JMX console exposure,
* web console exposure, status servlet info leakage, default credentials, and known CVEs
 */
package jbossaudit

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// isJBossApp checks if the target appears to be a JBoss application
func isJBossApp(flow *http.Flow) bool {
	if flow == nil || flow.Response == nil {
		return false
	}
	// Check Server header
	serverHeader := flow.Response.GetHeader("Server")
	if strings.Contains(strings.ToLower(serverHeader), "jboss") {
		return true
	}
	// Check X-Powered-By header
	poweredBy := flow.Response.GetHeader("X-Powered-By")
	if strings.Contains(strings.ToLower(poweredBy), "jboss") ||
		strings.Contains(strings.ToLower(poweredBy), "undertow") {
		return true
	}
	// Check response body for JBoss signatures
	body := flow.Response.Text
	if strings.Contains(body, "JBoss") ||
		strings.Contains(body, "jboss") ||
		strings.Contains(body, "org.jboss.") ||
		strings.Contains(body, "JBossWeb") {
		return true
	}
	// Check for JBoss-style error page
	if strings.Contains(body, "jboss-web") ||
		strings.Contains(body, "JBoss Management") {
		return true
	}
	return false
}

// JBossFingerprint detects JBoss via Server header and error pages
type JBossFingerprint struct{}

func (*JBossFingerprint) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("JBossAudit: fingerprint check for %s", flow.Request.URL().String())

			if !isJBossApp(flow) {
				return nil
			}

			// Extract version if available
			versionRe := regexp.MustCompile(`JBoss(?:Web)?/([\d\.]+)`)
			serverHeader := flow.Response.GetHeader("Server")
			poweredBy := flow.Response.GetHeader("X-Powered-By")
			var version string
			if matches := versionRe.FindStringSubmatch(serverHeader); len(matches) > 1 {
				version = matches[1]
			} else if matches := versionRe.FindStringSubmatch(poweredBy); len(matches) > 1 {
				version = matches[1]
			}

			v := a.NewWebVuln(flow.Request, flow.Response, nil)
			if v != nil {
				v.SetTargetURL(flow.Request.URL())
				v.Payload = "JBoss fingerprint detected"
				if version != "" {
					v.Add("version", version)
				}
				v.Add("server_header", serverHeader)
				v.Add("x_powered_by", poweredBy)
				a.OutputVuln(v)
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "jboss-audit/fingerprint",
			Plugin:   "jboss-audit",
			Category: "jboss-audit/fingerprint",
			Severity: model.SeverityInfo,
		},
	}
}

// JBossJMXConsole checks for exposed JMX Console and Web Console
type JBossJMXConsole struct{}

func (*JBossJMXConsole) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("JBossAudit: JMX console check for %s", flow.Request.URL().String())

			baseURL := flow.Request.URL()
			consolePaths := []struct {
				path        string
				description string
			}{
				{"/jmx-console/", "JBoss JMX Management Console"},
				{"/jmx-console/HtmlAdaptor", "JBoss JMX HTML Adaptor"},
				{"/jmx-console/HtmlAdaptor?action=displayMBeans", "JBoss JMX MBean listing"},
				{"/web-console/", "JBoss Web Console"},
				{"/web-console/ServerInfo.jsp", "JBoss Server Info"},
				{"/jboss-net/", "JBoss.NET endpoint"},
				{"/ws-console/", "JBoss Web Service Console"},
				{"/invoker/JMXInvokerServlet", "JBoss JMX Invoker Servlet"},
				{"/invoker/EJBInvokerServlet", "JBoss EJB Invoker Servlet"},
				{"/invoker/readonly/JMXInvokerServlet", "JBoss readonly JMX Invoker"},
			}

			for _, p := range consolePaths {
				testURL := http.UrlJoinPath(baseURL.String(), p.path)
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					continue
				}
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}

				isConsoleExposed := false

				// Check for JMX console signature
				if strings.Contains(p.path, "jmx-console") {
					if res.StatusCode == 200 &&
						(strings.Contains(res.Text, "JBoss JMX Management Console") ||
							strings.Contains(res.Text, "MBean Inspector") ||
							strings.Contains(res.Text, "HtmlAdaptor")) {
						isConsoleExposed = true
					}
				}

				// Check for web console signature
				if strings.Contains(p.path, "web-console") {
					if res.StatusCode == 200 &&
						(strings.Contains(res.Text, "ServerInfo.jsp") ||
							strings.Contains(res.Text, "HtmlAdaptor?action=displayMBeans") ||
							strings.Contains(res.Text, "jboss")) {
						isConsoleExposed = true
					}
				}

				// Check for invoker servlets - look for Java serialization content type
				if strings.Contains(p.path, "invoker/") {
					if res.StatusCode == 200 || res.StatusCode == 500 {
						contentType := res.GetHeader("Content-Type")
						if strings.Contains(contentType, "application/x-java-serialized-object") {
							isConsoleExposed = true
						}
						// Even 500 may indicate the servlet exists
						if res.StatusCode == 500 && strings.Contains(res.Text, "org.jboss.") {
							isConsoleExposed = true
						}
					}
				}

				// Check for ws-console
				if strings.Contains(p.path, "ws-console") && res.StatusCode == 200 {
					isConsoleExposed = true
				}

				// Check for jboss-net
				if strings.Contains(p.path, "jboss-net") && res.StatusCode == 200 {
					isConsoleExposed = true
				}

				if isConsoleExposed {
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
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "jboss-audit/jmx-console",
			Plugin:   "jboss-audit",
			Category: "jboss-audit/jmx-console",
			Severity: model.SeverityHigh,
		},
	}
}

// JBossStatusServlet checks for status servlet information leakage
type JBossStatusServlet struct{}

func (*JBossStatusServlet) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("JBossAudit: status servlet check for %s", flow.Request.URL().String())

			baseURL := flow.Request.URL()
			statusPaths := []struct {
				path        string
				description string
			}{
				{"/status", "JBoss Status Servlet"},
				{"/status?full=true", "JBoss Status Servlet (full detail)"},
				{"/status?XML=true", "JBoss Status Servlet (XML output)"},
			}

			for _, p := range statusPaths {
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
					// Check for JBoss/Tomcat status page content
					if strings.Contains(res.Text, "Server Status") ||
						strings.Contains(res.Text, "jvmRoute") ||
						strings.Contains(res.Text, "Connector") ||
						strings.Contains(res.Text, "maxThreads") ||
						strings.Contains(res.Text, "maxSpareThreads") ||
						strings.Contains(res.Text, "currentThreadCount") {
						v := a.NewWebVuln(req, res, nil)
						if v != nil {
							v.SetTargetURL(req.URL())
							v.Payload = p.path + " - " + p.description + " exposes server internals"
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
			ID:       "jboss-audit/status-servlet",
			Plugin:   "jboss-audit",
			Category: "jboss-audit/status-servlet",
			Severity: model.SeverityMedium,
		},
	}
}

// JBossDefaultCredentials tests default credentials on JMX console
type JBossDefaultCredentials struct{}

func (*JBossDefaultCredentials) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("JBossAudit: default credentials check for %s", flow.Request.URL().String())

			baseURL := flow.Request.URL()

			// Find JMX console path
			consolePaths := []string{"/jmx-console/", "/web-console/"}
			var consoleURL string
			for _, path := range consolePaths {
				testURL := http.UrlJoinPath(baseURL.String(), path)
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					continue
				}
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}
				if res.StatusCode == 401 {
					consoleURL = testURL
					break
				}
				if res.StatusCode == 200 {
					// Already accessible without auth - report as finding
					v := a.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(req.URL())
						v.Payload = path + " accessible without authentication"
						v.Add("credential", "none required")
						a.OutputVuln(v)
					}
					return nil
				}
			}

			if consoleURL == "" {
				return nil
			}

			// Default JBoss credentials
			defaultCreds := [][2]string{
				{"admin", "admin"},
				{"admin", "jboss"},
				{"admin", "password"},
				{"jboss", "jboss"},
				{"jboss", "admin"},
				{"guest", "guest"},
				{"user", "user"},
				{"operator", "operator"},
				{"monitor", "monitor"},
				{"admin", ""},
			}

			// Get baseline with wrong credentials
			wrongCred := base64.StdEncoding.EncodeToString([]byte("wscan_invalid:wscan_invalid"))
			baselineReq, _ := http.NewRequest("GET", consoleURL, nil)
			baselineReq.SetHeader("Authorization", "Basic "+wrongCred)
			baselineRes, err := a.HTTPClient.Respond(ctx, baselineReq)
			if err != nil {
				return nil
			}

			for _, cred := range defaultCreds {
				cred := cred
				credStr := base64.StdEncoding.EncodeToString([]byte(cred[0] + ":" + cred[1]))
				req, err := http.NewRequest("GET", consoleURL, nil)
				if err != nil {
					continue
				}
				req.SetHeader("Authorization", "Basic "+credStr)
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}
				if res.StatusCode >= 200 && res.StatusCode < 400 {
					// Compare with baseline
					if baselineRes != nil {
						if baselineRes.StatusCode == res.StatusCode {
							baselineLen := len(baselineRes.Text)
							resLen := len(res.Text)
							if baselineLen > 0 && resLen > 0 {
								ratio := float64(resLen) / float64(baselineLen)
								if ratio > 0.95 && ratio < 1.05 {
									continue
								}
							}
						}
					}
					v := a.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(req.URL())
						v.Payload = fmt.Sprintf("Default credentials: %s:%s", cred[0], cred[1])
						v.Add("username", cred[0])
						v.Add("password", cred[1])
						a.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "jboss-audit/default-credentials",
			Plugin:   "jboss-audit",
			Category: "jboss-audit/default-credentials",
			Severity: model.SeverityHigh,
		},
	}
}

// JBossDeserialization checks for JBoss deserialization vulnerabilities
type JBossDeserialization struct{}

func (*JBossDeserialization) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("JBossAudit: deserialization check for %s", flow.Request.URL().String())

			baseURL := flow.Request.URL()

			// Check for invoker servlets that accept serialized Java objects
			// These are the endpoints exploited in CVE-2015-7501 and CVE-2017-7504
			invokerPaths := []struct {
				path        string
				cve         string
				description string
			}{
				{"/invoker/JMXInvokerServlet", "CVE-2015-7501", "JBoss JMXInvokerServlet deserialization RCE"},
				{"/invoker/EJBInvokerServlet", "CVE-2015-7501", "JBoss EJBInvokerServlet deserialization RCE"},
				{"/invoker/readonly/JMXInvokerServlet", "CVE-2017-7504", "JBoss readonly JMXInvokerServlet deserialization RCE"},
				{"/invoker/readonly", "CVE-2017-7504", "JBoss readonly invoker deserialization RCE"},
				{"/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type%3DServerInfo", "CVE-2015-7501", "JBoss ServerInfo MBean exposure"},
				{"/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.deployer:service%3DBSHDeployer", "CVE-2015-7501", "JBoss BSHDeployer MBean exposure"},
				{"/web-console/Invoker", "CVE-2015-7501", "JBoss Web Console Invoker deserialization"},
			}

			for _, p := range invokerPaths {
				testURL := http.UrlJoinPath(baseURL.String(), p.path)
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					continue
				}
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}

				// Check for Java serialization indicators
				isVuln := false

				// 1. Content type indicates Java serialization
				contentType := res.GetHeader("Content-Type")
				if strings.Contains(contentType, "application/x-java-serialized-object") {
					isVuln = true
				}

				// 2. Response body starts with Java serialization magic bytes (0xACED0005)
				rawBody := res.GetRawBody()
				if len(rawBody) >= 4 && rawBody[0] == 0xAC && rawBody[1] == 0xED && rawBody[2] == 0x00 && rawBody[3] == 0x05 {
					isVuln = true
				}

				// 3. Check for MBean inspector (for JMX console paths)
				if strings.Contains(p.path, "HtmlAdaptor") {
					if res.StatusCode == 200 &&
						(strings.Contains(res.Text, "MBean Inspector") ||
							strings.Contains(res.Text, "BSHDeployer") ||
							strings.Contains(res.Text, "createScriptDeployment")) {
						isVuln = true
					}
				}

				// 4. Web console invoker with serialization content type
				if strings.Contains(p.path, "web-console/Invoker") {
					if res.StatusCode == 200 &&
						strings.Contains(contentType, "application/x-java-serialized-object") {
						isVuln = true
					}
				}

				if isVuln {
					v := a.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(req.URL())
						v.Payload = p.cve + ": " + p.description
						v.Add("cve", p.cve)
						v.Add("description", p.description)
						v.Add("path", p.path)
						a.OutputVuln(v)
					}
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "jboss-audit/deserialization",
			Plugin:   "jboss-audit",
			Category: "jboss-audit/deserialization",
			Severity: model.SeverityCritical,
		},
	}
}

// JBossMBeans checks for dangerous MBeans accessible via JMX console
type JBossMBeans struct{}

func (*JBossMBeans) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			logger.Debugf("JBossAudit: MBeans check for %s", flow.Request.URL().String())

			baseURL := flow.Request.URL()

			// Check for dangerous MBeans that could be exploited
			mbeanPaths := []struct {
				path        string
				mbeanName   string
				description string
			}{
				{"/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type%3DServer", "jboss.system:type=Server", "JBoss Server MBean"},
				{"/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type%3DServerInfo", "jboss.system:type=ServerInfo", "JBoss ServerInfo MBean"},
				{"/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss:service%3DJNDIView", "jboss:service=JNDIView", "JBoss JNDI View MBean"},
				{"/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.admin:service%3DDeploymentFileRepository", "jboss.admin:service=DeploymentFileRepository", "JBoss Deployment File Repository MBean"},
				{"/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.web:service%3DWebServer", "jboss.web:service=WebServer", "JBoss Web Server MBean"},
			}

			for _, p := range mbeanPaths {
				testURL := http.UrlJoinPath(baseURL.String(), p.path)
				req, err := http.NewRequest("GET", testURL, nil)
				if err != nil {
					continue
				}
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}
				if res.StatusCode == 200 &&
					strings.Contains(res.Text, "MBean Inspector") {
					v := a.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(req.URL())
						v.Payload = "MBean accessible: " + p.mbeanName + " - " + p.description
						v.Add("mbean", p.mbeanName)
						v.Add("description", p.description)
						a.OutputVuln(v)
					}
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "jboss-audit/mbeans",
			Plugin:   "jboss-audit",
			Category: "jboss-audit/mbeans",
			Severity: model.SeverityMedium,
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

// JBossAudit is the main plugin struct
type JBossAudit struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Close shuts down the plugin
func (*JBossAudit) Close() error {
	return nil
}

// DefaultConfig returns the default configuration
func (*JBossAudit) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "jboss-audit",
		Enabled: true,
	}}
	return config
}

// Fingers returns the detection rules
func (p *JBossAudit) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, (&JBossFingerprint{}).Finger())
	fingers = append(fingers, (&JBossJMXConsole{}).Finger())
	fingers = append(fingers, (&JBossStatusServlet{}).Finger())
	fingers = append(fingers, (&JBossDefaultCredentials{}).Finger())
	fingers = append(fingers, (&JBossDeserialization{}).Finger())
	fingers = append(fingers, (&JBossMBeans{}).Finger())
	return fingers
}

// GetConfig returns the current configuration
func (p *JBossAudit) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin
func (p *JBossAudit) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("JBossAudit Plugin init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}
