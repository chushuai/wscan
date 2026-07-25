/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package hostheader

import (
	"context"
	"strings"
	"sync/atomic"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/reverse"
	logger "wscan/core/utils/log"
)

// Config holds the plugin configuration.
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	MaxTests              int `json:"max_tests" yaml:"max_tests" #:"Maximum number of host header attack tests per scan"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// HostHeader is the plugin struct for Host Header Attack detection.
type HostHeader struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
	testCount int32
}

// Close shuts down the plugin.
func (*HostHeader) Close() error {
	return nil
}

// DefaultConfig returns the default plugin configuration.
func (*HostHeader) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "host-header",
			Enabled: true,
		},
		MaxTests: 10,
	}
}

// authKeywords are used to identify URLs related to password reset, login, and registration.
var authKeywords = []string{
	"reset",
	"password",
	"forget",
	"login",
	"auth",
	"signup",
	"register",
	"account",
	"recover",
	"changepassword",
}

// isAuthURL checks if the URL path contains authentication-related keywords.
func isAuthURL(urlPath string) bool {
	lowerPath := strings.ToLower(urlPath)
	for _, kw := range authKeywords {
		if strings.Contains(lowerPath, kw) {
			return true
		}
	}
	return false
}

// hostHeaderAttackFinger creates the Host Header Attack detection finger.
func (p *HostHeader) hostHeaderAttackFinger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			reqURL := flow.Request.URL().String()
			logger.Debugf("Start to detect Host Header Attack %s", reqURL)

			// Step 1: Check if the URL matches authentication-related patterns
			if !isAuthURL(flow.Request.URL().Path) {
				return nil
			}

			// Step 2: Enforce max tests limit
			currentCount := atomic.AddInt32(&p.testCount, 1)
			if currentCount > int32(p.getMaxTests()) {
				atomic.AddInt32(&p.testCount, -1)
				return nil
			}

			// Step 3: Register with reverse platform for callback verification
			unit := ab.Reverse.Register(nil)
			reverseDomainInfo, err := unit.GetQueryDomain()
			var reverseDomain string
			if err == nil && reverseDomainInfo != nil && reverseDomainInfo.Domain != "" {
				reverseDomain = reverseDomainInfo.Domain
			} else {
				// Fallback: extract host from the HTTP callback URL
				visitURL := unit.GetVisitURL()
				// visitURL format: http://host:port/i/... extract the host:port part
				if strings.HasPrefix(visitURL, "http://") {
					trimmed := strings.TrimPrefix(visitURL, "http://")
					parts := strings.SplitN(trimmed, "/", 2)
					if len(parts) > 0 {
						reverseDomain = parts[0]
					}
				}
			}

			if reverseDomain == "" {
				logger.Debug("Host Header Attack: failed to get reverse domain")
				return nil
			}

			// Step 4: Anti-false-positive - check that the normal response
			// doesn't already contain the injected domain
			normalResponse := flow.Response
			if normalResponse != nil && strings.Contains(normalResponse.Text, reverseDomain) {
				logger.Debugf("Host Header Attack: reverse domain already in normal response, skipping %s", reqURL)
				return nil
			}

			// Step 5: Send 3 variants of the request with modified headers
			variants := []struct {
				name        string
				modifyReq   func(*http.Request, string) *http.Request
				description string
			}{
				{
					name: "Host header injection",
					modifyReq: func(req *http.Request, domain string) *http.Request {
						param := &http.Parameter{
							Position: http.PositionHeader,
							Key:      "Host",
							Value:    domain,
						}
						return req.Mutate(param)
					},
					description: "Host header replaced with reverse domain",
				},
				{
					name: "X-Forwarded-Host injection",
					modifyReq: func(req *http.Request, domain string) *http.Request {
						param := &http.Parameter{
							Position: http.PositionHeader,
							Key:      "X-Forwarded-Host",
							Value:    domain,
						}
						return req.Mutate(param)
					},
					description: "X-Forwarded-Host header added with reverse domain",
				},
				{
					name: "Host + X-Forwarded-Host injection",
					modifyReq: func(req *http.Request, domain string) *http.Request {
						// First set the Host header
						hostParam := &http.Parameter{
							Position: http.PositionHeader,
							Key:      "Host",
							Value:    domain,
						}
						modifiedReq := req.Mutate(hostParam)
						// Then add X-Forwarded-Host header
						xfhParam := &http.Parameter{
							Position: http.PositionHeader,
							Key:      "X-Forwarded-Host",
							Value:    domain,
						}
						return modifiedReq.Mutate(xfhParam)
					},
					description: "Both Host and X-Forwarded-Host headers set to reverse domain",
				},
			}

			for _, variant := range variants {
				modifiedReq := variant.modifyReq(flow.Request, reverseDomain)
				res, err := ab.HTTPClient.Respond(ctx, modifiedReq)
				if err != nil {
					logger.Debugf("Host Header Attack: request failed for variant %s: %v", variant.name, err)
					continue
				}

				// Check if the injected domain is reflected in the response body
				vulnDetected := false
				if res != nil && strings.Contains(res.Text, reverseDomain) {
					vulnDetected = true
				}

				// Also check if the reverse platform received a callback
				// (the server may have made an HTTP request using the injected host)
				unit.OnVisit(func(event *reverse.Event) error {
					vulnDetected = true
					return nil
				})
				unit.Fetch(0)

				if vulnDetected {
					v := ab.NewWebVuln(modifiedReq, res, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = variant.description
						v.Add("variant", variant.name)
						v.Add("injected_domain", reverseDomain)
						v.Add("original_host", flow.Request.Host)
						ab.OutputVuln(v)
					}
					// Found a vulnerability with this variant; stop testing more variants
					return nil
				}
			}

			return nil
		},
		Channel:     "web-generic",
		NeedReverse: true,
		Binding: &model.VulnBinding{
			ID:       "host-header/default",
			Plugin:   "host-header/injection",
			Category: "host-header",
			Severity: model.SeverityHigh,
		},
	}
}

// getMaxTests returns the configured max tests value.
func (p *HostHeader) getMaxTests() int {
	cfg, ok := p.GetConfig().(*Config)
	if !ok || cfg == nil {
		return 10
	}
	if cfg.MaxTests <= 0 {
		return 10
	}
	return cfg.MaxTests
}

// Fingers returns the detection rules.
func (p *HostHeader) Fingers() []*base.Finger {
	return []*base.Finger{
		p.hostHeaderAttackFinger(),
	}
}

// GetConfig returns the current plugin configuration.
func (p *HostHeader) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin.
func (p *HostHeader) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("Host Header Attack plugin init")
	p.testCount = 0
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}
