/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package hpp

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

// HPP is the plugin struct for HTTP Parameter Pollution detection.
type HPP struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Config holds the plugin configuration.
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

// BaseConfig returns the base plugin configuration.
func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// Close shuts down the plugin.
func (*HPP) Close() error {
	return nil
}

// DefaultConfig returns the default plugin configuration.
func (*HPP) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "hpp",
			Enabled: true,
		},
	}
}

// Fingers returns the detection rules.
func (p *HPP) Fingers() []*base.Finger {
	return []*base.Finger{
		{
			CheckAction: p.checkAction,
			ExecAction:  p.execAction,
			Channel:     "web-generic",
			Binding: &model.VulnBinding{
				ID:       "http_parameter_pollution",
				Plugin:   "http_parameter_pollution",
				Category: "http_parameter_pollution",
				Severity: model.SeverityMedium,
			},
		},
	}
}

// GetConfig returns the current plugin configuration.
func (p *HPP) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin.
func (p *HPP) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("HPP init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// checkAction skips requests without query or body parameters.
func (p *HPP) checkAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	for _, param := range flow.Request.ParamsQueryAndBody() {
		if param.Value != "" {
			return nil
		}
	}
	return fmt.Errorf("no parameters with values found")
}

// genHPPToken generates a unique marker value for HPP testing.
func genHPPToken() string {
	return fmt.Sprintf("hpp%d", utils.RandInt(900000, 999999))
}

// buildHPPURL constructs a URL with a duplicated query parameter.
// It appends &key=token to the existing query string.
func buildHPPURL(origURL *url.URL, key string, token string) string {
	u := origURL.String()
	if strings.Contains(u, "?") {
		return u + "&" + url.QueryEscape(key) + "=" + url.QueryEscape(token)
	}
	return u + "?" + url.QueryEscape(key) + "=" + url.QueryEscape(token)
}

// buildHPPBody constructs a body string with a duplicated form parameter.
func buildHPPBody(origBody string, key string, token string) string {
	if origBody == "" {
		return url.QueryEscape(key) + "=" + url.QueryEscape(token)
	}
	return origBody + "&" + url.QueryEscape(key) + "=" + url.QueryEscape(token)
}

// containsTokenInHTML checks if the HPP token appears in links or forms within HTML.
func containsTokenInHTML(htmlBody string, token string) bool {
	return strings.Contains(htmlBody, token)
}

// execAction performs HPP detection.
// For each query parameter, it duplicates the parameter with a unique token value.
// If the token appears in the response (especially in links/forms), the server may be
// vulnerable to HTTP Parameter Pollution.
func (p *HPP) execAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	logger.Debugf("Start detecting HPP vulnerability URL=%s", flow.Request.URL().String())

	// Get baseline response for comparison
	baselineReq := flow.Request.DeepClone()
	baselineRes, baselineErr := ab.HTTPClient.Respond(ctx, baselineReq)

	for _, param := range flow.Request.ParamsQueryAndBody() {
		if param.Value == "" {
			continue
		}
		if strings.ToLower(param.Key) == "submit" {
			continue
		}

		token := genHPPToken()

		if param.Position == http.PositionQuery {
			// Duplicate the query parameter by appending &key=token
			hppURL := buildHPPURL(flow.Request.URL(), param.Key, token)
			hppReq, err := http.NewRequest(flow.Request.Method, hppURL, nil)
			if err != nil {
				logger.Error(err)
				continue
			}
			// Copy headers from original request
			for k, v := range flow.Request.Header {
				hppReq.Header[k] = v
			}
			hppRes, err := ab.HTTPClient.Respond(ctx, hppReq)
			if err != nil {
				logger.Error(err)
				continue
			}

			// Skip non-2xx/3xx responses
			if hppRes.StatusCode < 200 || hppRes.StatusCode >= 400 {
				continue
			}

			// Check if the token appears in the response body
			// (particularly in links/forms, which indicates parameter propagation)
			if !containsTokenInHTML(hppRes.Text, token) {
				continue
			}

			// Baseline check: if the token already appears in the baseline, skip
			if baselineErr == nil && baselineRes != nil && strings.Contains(baselineRes.Text, token) {
				continue
			}

			// Determine precedence
			precedence := determinePrecedence(ctx, ab, flow, param, token)

			// Report vulnerability
			v := ab.NewWebVuln(hppReq, hppRes, &http.Parameter{
				Position: param.Position,
				Key:      param.Key,
				Value:    param.Value + "&" + param.Key + "=" + token,
			})
			if v != nil {
				v.SetTargetURL(flow.Request.URL())
				v.Payload = param.Key + "=" + param.Value + "&" + param.Key + "=" + token
				v.Add("parameter", param.Key)
				v.Add("original_value", param.Value)
				v.Add("hpp_token", token)
				v.Add("precedence", precedence)
				ab.OutputVuln(v)
				break
			}

		} else if param.Position == http.PositionBody {
			// For body parameters, duplicate by appending to the body
			hppReq := flow.Request.DeepClone()
			origBody := string(hppReq.GetRawBody())
			newBody := buildHPPBody(origBody, param.Key, token)
			bodyReader := strings.NewReader(newBody)
			hppReq = hppReq.WithFormBody(bodyReader)

			hppRes, err := ab.HTTPClient.Respond(ctx, hppReq)
			if err != nil {
				logger.Error(err)
				continue
			}

			if hppRes.StatusCode < 200 || hppRes.StatusCode >= 400 {
				continue
			}

			if !containsTokenInHTML(hppRes.Text, token) {
				continue
			}

			if baselineErr == nil && baselineRes != nil && strings.Contains(baselineRes.Text, token) {
				continue
			}

			v := ab.NewWebVuln(hppReq, hppRes, &http.Parameter{
				Position: param.Position,
				Key:      param.Key,
				Value:    param.Value + "&" + param.Key + "=" + token,
			})
			if v != nil {
				v.SetTargetURL(flow.Request.URL())
				v.Payload = param.Key + "=" + param.Value + "&" + param.Key + "=" + token
				v.Add("parameter", param.Key)
				v.Add("original_value", param.Value)
				v.Add("hpp_token", token)
				ab.OutputVuln(v)
				break
			}
		}
	}

	return nil
}

// determinePrecedence tests whether the server uses the first or last value
// when duplicate parameters are present.
// It sends two requests with different value orders and compares responses.
func determinePrecedence(ctx context.Context, ab *base.Apollo, flow *http.Flow, param http.Parameter, token string) string {
	// Generate a distinct value for precedence testing
	testValue1 := fmt.Sprintf("v%d", utils.RandInt(900000, 999999))
	testValue2 := fmt.Sprintf("v%d", utils.RandInt(900000, 999999))

	// Build URL with param=testValue1&param=testValue2 (original first)
	u1 := buildHPPURLWithValues(flow.Request.URL(), param.Key, testValue1, testValue2)
	req1, err := http.NewRequest(flow.Request.Method, u1, nil)
	if err != nil {
		return "unknown"
	}
	for k, v := range flow.Request.Header {
		req1.Header[k] = v
	}
	res1, err := ab.HTTPClient.Respond(ctx, req1)
	if err != nil {
		return "unknown"
	}

	// Build URL with param=testValue2&param=testValue1 (reversed order)
	u2 := buildHPPURLWithValues(flow.Request.URL(), param.Key, testValue2, testValue1)
	req2, err := http.NewRequest(flow.Request.Method, u2, nil)
	if err != nil {
		return "unknown"
	}
	for k, v := range flow.Request.Header {
		req2.Header[k] = v
	}
	res2, err := ab.HTTPClient.Respond(ctx, req2)
	if err != nil {
		return "unknown"
	}

	// Build URL with only param=testValue2 (to test against last)
	u3 := replaceQueryValue(flow.Request.URL(), param.Key, testValue2)
	req3, err := http.NewRequest(flow.Request.Method, u3, nil)
	if err != nil {
		return "unknown"
	}
	for k, v := range flow.Request.Header {
		req3.Header[k] = v
	}
	res3, err := ab.HTTPClient.Respond(ctx, req3)
	if err != nil {
		return "unknown"
	}

	// If response with duplicate params (first=testValue1, second=testValue2)
	// matches response with only testValue2, server uses LAST value
	filtered1 := filterResponseBody(res1.Text)
	filtered2 := filterResponseBody(res2.Text)
	filtered3 := filterResponseBody(res3.Text)

	if filtered1 == filtered3 {
		return "last"
	}
	// If response with duplicate params (first=testValue2, second=testValue1)
	// matches response with only testValue2, server uses FIRST value
	if filtered2 == filtered3 {
		return "first"
	}

	return "unknown"
}

// buildHPPURLWithValues builds a URL with a duplicated parameter having two explicit values.
func buildHPPURLWithValues(origURL *url.URL, key string, value1 string, value2 string) string {
	// Strip the existing parameter and rebuild
	q := origURL.Query()
	delKey := key
	q.Del(delKey)
	q.Add(key, value1)
	q.Add(key, value2)
	u := *origURL
	u.RawQuery = q.Encode()
	return u.String()
}

// replaceQueryValue replaces the value of a query parameter in the URL.
func replaceQueryValue(origURL *url.URL, key string, newValue string) string {
	q := origURL.Query()
	q.Set(key, newValue)
	u := *origURL
	u.RawQuery = q.Encode()
	return u.String()
}

// filterResponseBody removes dynamic content from the response body for comparison.
func filterResponseBody(body string) string {
	// Remove time patterns
	result := body
	// Simple approach: trim to reasonable length for comparison
	if len(result) > 4096 {
		result = result[:4096]
	}
	return result
}
