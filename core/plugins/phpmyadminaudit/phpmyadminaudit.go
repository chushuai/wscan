/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package phpmyadminaudit

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// Config phpMyAdmin 审计插件配置
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// PhpMyAdminAudit phpMyAdmin 审计插件
type PhpMyAdminAudit struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

func (*PhpMyAdminAudit) Close() error { return nil }

func (*PhpMyAdminAudit) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "phpmyadmin-audit", Enabled: true},
	}
}

func (p *PhpMyAdminAudit) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *PhpMyAdminAudit) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("PhpMyAdminAudit plugin init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// Common phpMyAdmin URL paths (from AWVS reference)
var phpMyAdminPaths = []string{
	"/phpmyadmin/",
	"/phpMyAdmin/",
	"/pma/",
	"/mysql/",
	"/db/",
	"/dbadmin/",
	"/mysqladmin/",
	"/PMA/",
	"/myadmin/",
	"/phpmyadmin2/",
	"/phpMyAdmin2/",
	"/admin/pma/",
	"/admin/phpmyadmin/",
	"/admin/mysql/",
	"/phpmyadmin/main.php",
	"/phpMyAdmin/main.php",
	"/pma/main.php",
	"/mysql/main.php",
	"/db/main.php",
	"/dbadmin/main.php",
	"/mysqladmin/main.php",
	"/PMA/main.php",
	"/myadmin/main.php",
	"/phpmyadmin2/main.php",
	"/phpMyAdmin2/main.php",
	"/admin/pma/main.php",
	"/admin/phpmyadmin/main.php",
	"/admin/mysql/main.php",
	"/admin/pma/",
	"/admin/phpmyadmin/",
	"/admin/mysql/",
}

// phpMyAdmin fingerprint patterns
var pmaFingerprints = []string{
	// Default root password warning
	"Your configuration file contains settings (root with no password)",
	// config.sample.inc.php warning
	"which is used by the setup script, still exists in your phpMyAdmin directory",
	// Query window link
	"querywindow.php",
	// Database operations link
	"db_operations.php",
	// Server version display
	"li_server_version",
	// phpMyAdmin logo/title
	"phpMyAdmin",
}

// Version extraction regexes
var versionRegexes = []*regexp.Regexp{
	regexp.MustCompile(`phpMyAdmin\s+(\d+\.\d+\.\d+)`),
	regexp.MustCompile(`Version\s+information.*?(\d+\.\d+\.\d+)`),
	regexp.MustCompile(`PMA_VERSION\s*["']?\s*=\s*["'](\d+\.\d+\.\d+)["']`),
	regexp.MustCompile(`version\s*["']?\s*=\s*["'](\d+\.\d+\.\d+)["']`),
}

// phpMyAdmin CVE mapping (version -> CVEs)
var pmaCVEs = map[string][]string{
	"4.0": {"CVE-2013-3238", "CVE-2013-3239", "CVE-2013-3240"},
	"4.1": {"CVE-2014-1879"},
	"4.2": {"CVE-2014-8959", "CVE-2014-8960", "CVE-2014-8961", "CVE-2014-8962", "CVE-2014-8963"},
	"4.3": {"CVE-2015-2201", "CVE-2015-7870"},
	"4.4": {"CVE-2015-8770", "CVE-2015-8771", "CVE-2015-8772"},
	"4.6": {"CVE-2016-2040", "CVE-2016-2555", "CVE-2016-2561", "CVE-2016-5715"},
	"4.7": {"CVE-2017-10046", "CVE-2017-10047", "CVE-2017-10049"},
	"4.8": {"CVE-2018-12662", "CVE-2018-12663"},
	"4.9": {"CVE-2019-12922"},
	"5.0": {"CVE-2020-0531", "CVE-2020-0532", "CVE-2020-0533"},
	"5.1": {"CVE-2021-27861"},
}

// doRequest sends an HTTP request and returns the request, response, and error.
func doRequest(apollo *base.Apollo, method, rawURL string) (*http.Request, *http.Response, error) {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := apollo.HTTPClient.Respond(context.Background(), req)
	if err != nil {
		return nil, nil, err
	}
	return req, resp, nil
}

// doRequestWithBody sends an HTTP request with a body.
func doRequestWithBody(apollo *base.Apollo, method, rawURL, body, contentType string) (*http.Request, *http.Response, error) {
	req, err := http.NewRequest(method, rawURL, strings.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	if contentType != "" {
		req.SetHeader("Content-Type", contentType)
	}
	resp, err := apollo.HTTPClient.Respond(context.Background(), req)
	if err != nil {
		return nil, nil, err
	}
	return req, resp, nil
}

// makeVuln creates and outputs a vulnerability.
func makeVuln(apollo *base.Apollo, req *http.Request, resp *http.Response, vulnID, category, payload string, extra map[string]any) {
	v := apollo.NewWebVuln(req, resp, nil)
	if v == nil {
		return
	}
	v.SetTargetURL(req.URL())
	v.Payload = payload
	if extra != nil {
		for k, val := range extra {
			v.Extra[k] = val
		}
	}
	apollo.OutputVuln(v)
}

// extractVersion tries to extract phpMyAdmin version from response body.
func extractVersion(body string) string {
	for _, re := range versionRegexes {
		matches := re.FindStringSubmatch(body)
		if len(matches) >= 2 {
			return matches[1]
		}
	}
	return ""
}

// getCVEsForVersion returns known CVEs for a given phpMyAdmin version prefix.
func getCVEsForVersion(version string) []string {
	// Extract major.minor prefix (e.g., "4.8.3" -> "4.8")
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		prefix := parts[0] + "." + parts[1]
		if cves, ok := pmaCVEs[prefix]; ok {
			return cves
		}
	}
	return nil
}

func (p *PhpMyAdminAudit) Fingers() []*base.Finger {
	return []*base.Finger{
		// phpMyAdmin 暴露检测
		{
			Channel: "website",
			Binding: &model.VulnBinding{
				ID:       "phpmyadmin_exposed",
				Plugin:   "phpmyadminaudit",
				Category: "phpmyadmin_exposed",
				Severity: model.SeverityHigh,
			},
			CheckAction: func(ctx context.Context, apollo *base.Apollo) error {
				flow := apollo.GetTargetFlow()
				if flow == nil || flow.Request == nil {
					return fmt.Errorf("no flow available")
				}
				return nil
			},
			ExecAction: func(ctx context.Context, apollo *base.Apollo) error {
				flow := apollo.GetTargetFlow()
				if flow == nil || flow.Request == nil {
					return nil
				}
				baseURL := flow.Request.URL().String()

				// Step 1: Fingerprint - check common phpMyAdmin paths
				for _, path := range phpMyAdminPaths {
					rawURL := http.UrlJoinPath(baseURL, path)
					req, resp, err := doRequest(apollo, "GET", rawURL)
					if err != nil || resp.StatusCode != 200 {
						continue
					}

					body := resp.Text
					matched := false
					matchedPattern := ""
					for _, pattern := range pmaFingerprints {
						if strings.Contains(body, pattern) {
							matched = true
							matchedPattern = pattern
							break
						}
					}

					if !matched {
						continue
					}

					extra := map[string]any{
						"path":    path,
						"matched": matchedPattern,
					}

					// Step 2: Version detection
					version := extractVersion(body)
					if version != "" {
						extra["version"] = version
						// Step 3: Known CVEs
						cves := getCVEsForVersion(version)
						if len(cves) > 0 {
							extra["cves"] = cves
						}
					}

					makeVuln(apollo, req, resp, "phpmyadmin_exposed", "phpmyadmin_exposed",
						"phpMyAdmin interface exposed at "+path, extra)

					// Step 4: Try README for version if not found on main page
					if version == "" {
						readmeURL := http.UrlJoinPath(rawURL, "README")
						readmeReq, readmeResp, err := doRequest(apollo, "GET", readmeURL)
						if err == nil && readmeResp.StatusCode == 200 {
							readmeVersion := extractVersion(readmeResp.Text)
							if readmeVersion != "" {
								cves := getCVEsForVersion(readmeVersion)
								makeVuln(apollo, readmeReq, readmeResp, "phpmyadmin_version_exposed", "phpmyadmin_version_exposed",
									"phpMyAdmin version exposed in README", map[string]any{
										"version": readmeVersion,
										"cves":    cves,
									})
							}
						}
					}

					// Step 5: Config exposure check
					configPaths := []string{
						"config.inc.php",
						"config.inc.php.old",
						"config.default.php",
						".htaccess",
					}
					for _, configFile := range configPaths {
						configURL := http.UrlJoinPath(rawURL, configFile)
						configReq, configResp, err := doRequest(apollo, "GET", configURL)
						if err != nil || configResp.StatusCode != 200 {
							continue
						}
						configBody := configResp.Text
						// Check if it contains actual PHP config content (not just empty or redirect)
						if strings.Contains(configBody, "$cfg") || strings.Contains(configBody, "php") {
							makeVuln(apollo, configReq, configResp, "phpmyadmin_config_exposed", "phpmyadmin_config_exposed",
								"phpMyAdmin config file exposed: "+configFile, map[string]any{
									"config_file": configFile,
								})
						}
					}

					// Step 6: Default credentials test
					// Try common paths for login form
					loginPaths := []string{"index.php", "login.php"}
					credentials := []struct {
						username string
						password string
					}{
						{"root", ""},
						{"root", "root"},
						{"root", "password"},
						{"root", "mysql"},
						{"root", "toor"},
						{"admin", "admin"},
						{"admin", "password"},
						{"mysql", "mysql"},
					}

					for _, loginPath := range loginPaths {
						loginURL := http.UrlJoinPath(rawURL, loginPath)
						// First check if login page exists
						_, loginResp, err := doRequest(apollo, "GET", loginURL)
						if err != nil || loginResp.StatusCode != 200 {
							continue
						}
						if !strings.Contains(loginResp.Text, "phpMyAdmin") {
							continue
						}

						// Test each credential
						for _, cred := range credentials {
							postData := fmt.Sprintf("pma_username=%s&pma_password=%s&server=1&lang=en", cred.username, cred.password)
							postReq, postResp, err := doRequestWithBody(apollo, "POST", loginURL, postData, "application/x-www-form-urlencoded")
							if err != nil {
								continue
							}
							// Successful login typically redirects (302) or shows a different page
							if postResp.StatusCode == 302 || (postResp.StatusCode == 200 &&
								!strings.Contains(postResp.Text, "Access denied") &&
								!strings.Contains(postResp.Text, "Cannot log in")) {
								makeVuln(apollo, postReq, postResp, "phpmyadmin_weak_credentials", "phpmyadmin_weak_credentials",
									fmt.Sprintf("Weak credentials: %s/%s", cred.username, cred.password), map[string]any{
										"username": cred.username,
										"password": cred.password,
									})
								break // One successful credential is enough
							}
						}
						break // One working login path is enough
					}

					// Found phpMyAdmin on first matching path, stop checking others
					return nil
				}

				return nil
			},
		},
	}
}
