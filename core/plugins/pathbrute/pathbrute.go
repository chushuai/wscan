/*
*
2 * @Author: shaochuyu
3 * @Date: 5/24/26
4
*/

package pathbrute

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

var CommonPaths = []string{
	"/admin", "/login", "/api", "/dashboard", "/config",
	"/backup", "/test", "/debug", "/console", "/manager",
	"/wp-admin", "/phpmyadmin", "/server-status", "/.env",
	"/.git/config", "/robots.txt", "/sitemap.xml", "/actuator",
	"/swagger-ui.html", "/api-docs", "/v1/api", "/v2/api",
	"/health", "/status", "/info", "/metrics", "/env",
	"/trace", "/dump", "/heapdump", "/threaddump",
	"/.htaccess", "/.svn/entries", "/WEB-INF/web.xml",
	"/crossdomain.xml", "/clientaccesspolicy.xml",
	"/elmah.axd", "/trace.axd", "/error.log", "/access.log",
	"/wp-config.php.bak", "/database.yml", "/config.json",
	"/package.json", "/composer.json", "/.DS_Store",
	"/id_rsa", "/id_dsa", "/.bash_history",
	"/cgi-bin/", "/bin/", "/tmp/", "/uploads/",
	"/static/", "/assets/", "/public/", "/dist/",
	"/build/", "/coverage/", "/doc/", "/docs/",
	"/api/v1/users", "/api/v2/users", "/api/health",
	"/oauth/token", "/auth/login", "/auth/register",
	"/graphql", "/graphiql", "/playground",
	"/.well-known/security.txt", "/security.txt",
	"/favicon.ico", "/apple-touch-icon.png",
	"/manifest.json", "/service-worker.js",
	"/sw.js", "/workbox-sw.js", "/precache-manifest.js",
	"/index.php", "/index.asp", "/index.jsp",
	"/default.aspx", "/main.py", "/app.py",
	"/server.js", "/index.js", "/run.py",
	"/Makefile", "/Dockerfile", "/docker-compose.yml",
	"/kubernetes.yaml", "/k8s.yaml", "/deploy.yaml",
	"/ci.yml", "/.github/workflows/main.yml",
	"/jenkins/", "/gitlab/", "/bitbucket/",
	"/sonarqube/", "/nexus/", "/artifactory/",
	"/consul/", "/etcd/", "/zookeeper/",
	"/redis/", "/mongo/", "/elasticsearch/",
	"/prometheus/", "/grafana/", "/kibana/",
	"/jaeger/", "/zipkin/", "/traefik/",
	"/nginx/", "/apache/", "/tomcat/",
	"/drupal/", "/joomla/", "/wordpress/",
}

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

type notFoundBaseline struct {
	resp1 *http.Response
	resp2 *http.Response // second random path response for comparison
}

type PathBrute struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
	notFoundCache map[string]*notFoundBaseline
	cacheMu       sync.Mutex
}

func (*PathBrute) Close() error { return nil }

func (*PathBrute) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "pathbrute", Enabled: true},
	}
}

// check404 establishes a 404 baseline by requesting two random paths and comparing them
func (p *PathBrute) check404(ctx context.Context, apollo *base.Apollo, baseURL fmt.Stringer) *notFoundBaseline {
	hostKey := baseURL.String()
	p.cacheMu.Lock()
	if p.notFoundCache == nil {
		p.notFoundCache = make(map[string]*notFoundBaseline)
	}
	p.cacheMu.Unlock()

	p.cacheMu.Lock()
	if bl, exists := p.notFoundCache[hostKey]; exists {
		p.cacheMu.Unlock()
		return bl
	}
	p.cacheMu.Unlock()

	// Request two different random paths to establish baseline
	var resp1, resp2 *http.Response
	for idx := 0; idx < 2; idx++ {
		randomPath := "/" + utils.RandLetters(16)
		rawURL := fmt.Sprintf("%s%s", hostKey, randomPath)
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			continue
		}
		r, err := apollo.HTTPClient.Respond(ctx, req)
		if err != nil {
			continue
		}
		if idx == 0 {
			resp1 = r
		} else {
			resp2 = r
		}
	}

	bl := &notFoundBaseline{resp1: resp1, resp2: resp2}
	p.cacheMu.Lock()
	p.notFoundCache[hostKey] = bl
	p.cacheMu.Unlock()

	return bl
}

// notFoundKeywords are common keywords found in custom 404 pages
var notFoundKeywords = []string{"not found", "not exist", "no found", "page not found", "找不到", "页面不存在", "file not found"}

// bodyContainsNotFound checks if the response body contains 404 indicator keywords
func bodyContainsNotFound(body string) bool {
	lower := strings.ToLower(body)
	for _, kw := range notFoundKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// bodySimilarity returns a similarity ratio between two strings (0.0-1.0)
func bodySimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	lenA, lenB := len(a), len(b)
	if lenA == 0 && lenB == 0 {
		return 1.0
	}
	if lenA == 0 || lenB == 0 {
		return 0.0
	}
	// Use length ratio as a quick similarity approximation
	minLen, maxLen := lenA, lenB
	if minLen > maxLen {
		minLen, maxLen = maxLen, minLen
	}
	lengthRatio := float64(minLen) / float64(maxLen)
	// If lengths are very different, not similar
	if lengthRatio < 0.5 {
		return lengthRatio * 0.5
	}
	// Compare common prefix/suffix lengths as content similarity signal
	common := 0
	minCheck := minLen
	if minCheck > 512 {
		minCheck = 512
	}
	for i := 0; i < minCheck; i++ {
		if a[i] == b[i] {
			common++
		}
	}
	prefixRatio := float64(common) / float64(minCheck)
	return 0.5*lengthRatio + 0.5*prefixRatio
}

// isCustom404 checks if a response looks like a custom 404 page (status 200 but actually not found)
func isCustom404(resp *http.Response, bl *notFoundBaseline) bool {
	if bl == nil {
		return false
	}

	// Method 1: Check body for 404 keywords
	if bodyContainsNotFound(resp.Text) {
		return true
	}

	// Method 2: Compare with 404 baseline responses
	for _, baseline := range []*http.Response{bl.resp1, bl.resp2} {
		if baseline == nil {
			continue
		}
		// If baseline also returns 200, compare body similarity
		if baseline.StatusCode >= 200 && baseline.StatusCode < 300 {
			sim := bodySimilarity(resp.Text, baseline.Text)
			// High similarity with random-path response means this is likely the same custom 404 page
			if sim > 0.8 {
				return true
			}
		}
	}

	// Method 3: If two baseline responses exist and are similar to each other (same custom 404 page),
	// and the target response has very similar body length, it's likely also the custom 404
	if bl.resp1 != nil && bl.resp2 != nil {
		baselineSim := bodySimilarity(bl.resp1.Text, bl.resp2.Text)
		if baselineSim > 0.8 {
			// The site has a consistent custom 404 page
			targetSim := bodySimilarity(resp.Text, bl.resp1.Text)
			if targetSim > 0.7 {
				return true
			}
		}
	}

	return false
}

// domStructure extracts the HTML tag name sequence from the body.
// Only tag names are extracted (not attributes or text content), which provides
// a noise-resistant structural fingerprint. Two catch-all pages that share the
// same template will produce identical or very similar tag name sequences even
// when their dynamic content (user-injected payloads) differs.
//
// Special markup constructs (<?...?>, <!DOCTYPE...>, <!-- ... -->, <![CDATA[...]]>)
// are skipped entirely since they are not real HTML elements.
func domStructure(htmlBody string) string {
	var tags []string
	i := 0
	for i < len(htmlBody) {
		if htmlBody[i] != '<' {
			i++
			continue
		}
		// Skip special markup: <?...?>, <!DOCTYPE...>, <!-- ... -->, <![CDATA[...]]>
		if i+1 < len(htmlBody) && (htmlBody[i+1] == '?' || htmlBody[i+1] == '!') {
			i++
			for i < len(htmlBody) && htmlBody[i] != '>' {
				i++
			}
			if i < len(htmlBody) {
				i++
			}
			continue
		}
		// Extract tag name from opening/closing tag
		i++ // skip '<'
		closing := false
		if i < len(htmlBody) && htmlBody[i] == '/' {
			closing = true
			i++
		}
		// Read tag name (alphanumeric characters)
		start := i
		for i < len(htmlBody) && isAlphaNum(htmlBody[i]) {
			i++
		}
		if i > start {
			tagName := strings.ToLower(htmlBody[start:i])
			if closing {
				tags = append(tags, "/"+tagName)
			} else {
				tags = append(tags, tagName)
			}
		}
		// Skip to end of tag
		for i < len(htmlBody) && htmlBody[i] != '>' {
			i++
		}
		if i < len(htmlBody) {
			i++
		}
	}
	return strings.Join(tags, " ")
}

// isAlphaNum checks if a byte is an alphanumeric character (for tag name extraction)
func isAlphaNum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// verifyWithRandomSuffix performs secondary verification by requesting the same path
// with a random suffix appended. If the server returns similar content for both paths,
// it's likely a catch-all route (SPA, default handler, etc.) that serves the same
// page regardless of the path — meaning the original discovery is a false positive.
//
// Example:
//
//	Discovered:  GET /env → 200 + "Readme" page
//	Verification: GET /env_aQx7kM9p → 200 + "Readme" page (very similar)
//	→ catch-all route → false positive
//
// Returns true if the discovery appears to be a real endpoint (not a catch-all).
func (p *PathBrute) verifyWithRandomSuffix(ctx context.Context, apollo *base.Apollo, req *http.Request, resp *http.Response) bool {
	originalPath := req.URL().Path
	// Append random suffix to create a path that should NOT exist on a real endpoint
	verifyPath := originalPath + "_" + utils.RandLetters(8)
	verifyURL := fmt.Sprintf("%s://%s%s", req.URL().Scheme, req.URL().Host, verifyPath)

	verifyReq, err := http.NewRequest("GET", verifyURL, nil)
	if err != nil {
		logger.Debugf("pathbrute: verify request creation failed for %s: %v", verifyURL, err)
		return true // 无法验证，假定发现有效
	}

	verifyResp, err := apollo.HTTPClient.Respond(ctx, verifyReq)
	if err != nil {
		logger.Debugf("pathbrute: verify request failed for %s: %v", verifyURL, err)
		return true // 无法验证，假定发现有效
	}

	// 如果状态码不同，说明原始路径是真实端点
	// （真实端点对 /env 返回 200，对 /env_random 返回 404）
	if verifyResp.StatusCode != resp.StatusCode {
		logger.Debugf("pathbrute: verification passed for %s - status codes differ (%d vs %d)",
			originalPath, resp.StatusCode, verifyResp.StatusCode)
		return true
	}

	// 状态码相同，比较 body 原文相似度
	bodySim := bodySimilarity(resp.Text, verifyResp.Text)

	// 比较 DOM 骨架相似度（去除文本内容，只比较标签结构）
	// 这能处理动态内容导致原文相似度偏低的情况
	structA := domStructure(resp.Text)
	structB := domStructure(verifyResp.Text)
	structSim := bodySimilarity(structA, structB)

	// body 原文相似度 > 0.8 或 DOM 骨架相似度 > 0.9 → catch-all 路由
	if bodySim > 0.8 || structSim > 0.9 {
		logger.Debugf("pathbrute: verification rejected %s as catch-all (bodySim=%.2f, structSim=%.2f)",
			originalPath, bodySim, structSim)
		return false
	}

	logger.Debugf("pathbrute: verification passed for %s (bodySim=%.2f, structSim=%.2f)",
		originalPath, bodySim, structSim)
	return true
}

// isValidDiscovery determines if a response is a valid path discovery
func (p *PathBrute) isValidDiscovery(resp *http.Response, bl *notFoundBaseline) bool {
	// Accept 2xx status codes
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Check for custom 404 page returning 200
		if isCustom404(resp, bl) {
			return false
		}
		// Empty body with 200 is suspicious — likely a default page or custom 404
		if len(strings.TrimSpace(resp.Text)) == 0 {
			return false
		}
		return true
	}
	// Report 3xx redirects
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return true
	}
	return false
}

func (p *PathBrute) Fingers() []*base.Finger {
	return []*base.Finger{
		{
			Channel: "website",
			Binding: &model.VulnBinding{
				ID:       "pathbrute/default",
				Plugin:   "pathbrute",
				Category: "pathbrute",
				Severity: model.SeverityLow,
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
				if flow == nil {
					return nil
				}
				baseURL := flow.Request.URL()

				// Establish 404 baseline for this host
				bl := p.check404(ctx, apollo, baseURL)

				submitted := 0
				for _, path := range CommonPaths {
					rawURL := fmt.Sprintf("%s://%s%s", baseURL.Scheme, baseURL.Host, path)
					req, err := http.NewRequest("GET", rawURL, nil)
					if err != nil {
						continue
					}
					// Capture closure variables
					taskName := fmt.Sprintf("pathbrute:%s", path)
					capturedReq := req
					capturedBL := bl

					err = apollo.SubmitTask(base.AsyncTask{
						Name: taskName,
						Fn: func() {
							resp, err := apollo.HTTPClient.Respond(context.Background(), capturedReq)
							if err != nil {
								logger.Debugf("pathbrute: %s failed: %v", taskName, err)
								return
							}

							if p.isValidDiscovery(resp, capturedBL) {
								// 二次验证：检测 catch-all 路由（对同路径追加随机后缀再请求，
								// 若返回相似内容则说明不是真实端点）
								if !p.verifyWithRandomSuffix(context.Background(), apollo, capturedReq, resp) {
									logger.Debugf("pathbrute: %s filtered as catch-all route", rawURL)
									return
								}
								if isCustom404(resp, bl) {
									return
								}
								logger.Infof("pathbrute: found %s (%d)", rawURL, resp.StatusCode)
								v := apollo.NewWebVuln(capturedReq, resp, nil)
								if v != nil {
									v.SetTargetURL(capturedReq.URL())
									v.Payload = path
									apollo.OutputVuln(v)
								}
							}
						},
					})
					if err != nil {
						logger.Debugf("pathbrute: failed to submit task %s: %v", taskName, err)
					} else {
						submitted++
					}
				}
				logger.Infof("pathbrute: submitted %d path tasks for %s", submitted, baseURL.String())
				return nil
			},
		},
	}
}

func (p *PathBrute) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *PathBrute) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("PathBrute plugin init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}
