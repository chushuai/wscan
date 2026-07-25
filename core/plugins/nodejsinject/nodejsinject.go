/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package nodejsinject

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

// NodeJSInject is the plugin struct for Node.js injection detection.
type NodeJSInject struct {
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
func (*NodeJSInject) Close() error {
	return nil
}

// DefaultConfig returns the default plugin configuration.
func (*NodeJSInject) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "nodejs-inject",
			Enabled: true,
		},
	}
}

// Fingers returns the detection rules.
func (p *NodeJSInject) Fingers() []*base.Finger {
	return []*base.Finger{
		{
			CheckAction: p.checkAction,
			ExecAction:  p.execAction,
			Channel:     "web-generic",
			Binding: &model.VulnBinding{
				ID:       "nodejs-injection",
				Plugin:   "nodejs-inject",
				Category: "nodejs-inject",
				Severity: model.SeverityCritical,
			},
		},
	}
}

// GetConfig returns the current plugin configuration.
func (p *NodeJSInject) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin.
func (p *NodeJSInject) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("NodeJSInject init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// checkAction skips requests without parameters.
func (p *NodeJSInject) checkAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	for _, param := range flow.Request.ParamsAll() {
		if param.Value != "" {
			return nil
		}
	}
	return fmt.Errorf("no parameters with values found")
}

// isNodeJSServer checks if the server appears to be running Node.js
// by examining response headers like X-Powered-By.
func isNodeJSServer(res *http.Response) bool {
	poweredBy := res.GetHeader("X-Powered-By")
	if poweredBy == "" {
		poweredBy = res.GetHeader("x-powered-by")
	}
	nodeIndicators := []string{"Express", "Next.js", "Nuxt", "Koa", "Fastify", "Hapi", "Sails", "LoopBack", "Meteor", "Node.js"}
	for _, indicator := range nodeIndicators {
		if strings.Contains(poweredBy, indicator) {
			return true
		}
	}
	// Also check Server header
	server := res.GetHeader("Server")
	if strings.Contains(server, "Node") || strings.Contains(server, "Express") {
		return true
	}
	return false
}

// Error patterns indicating Node.js runtime errors
var nodeJSErrorPatterns = []struct {
	Pattern string
	Regex   *regexp.Regexp
}{
	{Pattern: "SyntaxError: Unexpected token", Regex: nil},
	{Pattern: "SyntaxError: Unexpected identifier", Regex: nil},
	{Pattern: "SyntaxError: Unexpected number", Regex: nil},
	{Pattern: "SyntaxError: Unexpected end of input", Regex: nil},
}

var referenceErrorRegex = regexp.MustCompile(`ReferenceError: .*? is not defined`)

// checkNodeJSErrors checks if the response contains Node.js error messages.
func checkNodeJSErrors(responseText string) (bool, string) {
	for _, pattern := range nodeJSErrorPatterns {
		if strings.Contains(responseText, pattern.Pattern) {
			return true, pattern.Pattern
		}
	}
	if match := referenceErrorRegex.FindString(responseText); match != "" {
		return true, match
	}
	return false, ""
}

// genErrorPayloads generates error-based detection payloads.
// These inject malformed Node.js expressions that should trigger
// SyntaxError or ReferenceError if evaluated by the Node.js runtime.
func genErrorPayloads() []NodeJSErrorPayload {
	marker := fmt.Sprintf("__nodejs_%d__", utils.RandInt(900000, 999999))
	return []NodeJSErrorPayload{
		// Inject an undefined variable name - should trigger ReferenceError
		{Payload: marker, Description: "undefined variable injection", ExpectedError: "is not defined"},
		// Inject typeof expressions - if evaluated, "function" or "object" appears in response
		{Payload: "typeof require", Description: "typeof require check", ExpectedError: "function"},
		{Payload: "typeof process", Description: "typeof process check", ExpectedError: "object"},
		// Inject syntax-breaking expressions
		{Payload: ";;node;;", Description: "syntax breaker injection", ExpectedError: "SyntaxError"},
	}
}

// NodeJSErrorPayload represents an error-based detection payload.
type NodeJSErrorPayload struct {
	Payload       string
	Description   string
	ExpectedError string
}

// genTimePayloads generates time-based detection payloads.
// These inject JavaScript timing expressions that cause measurable delays
// if evaluated by the Node.js runtime.
func genTimePayloads() []NodeJSTimePayload {
	// Generate a random variable name to avoid collision
	randVar := "x" + utils.RandLower(5)
	// Base timing function: busy-wait loop in JavaScript
	// (function(){if(typeof randVar==="undefined"){var a=new Date();do{var b=new Date();}while(b-a<{sleep});randVar=1;}}())
	baseFn := fmt.Sprintf(
		"(function(){if(typeof %s===\"undefined\"){var a=new Date();do{var b=new Date();}while(b-a<{sleep});%s=1;}}())",
		randVar, randVar,
	)
	return []NodeJSTimePayload{
		// Direct injection
		{Payload: baseFn, Prefix: "", Suffix: "", Description: "direct time-based injection"},
		// Addition context: +payload+
		{Payload: baseFn, Prefix: "+", Suffix: "+", Description: "addition context time-based injection"},
		// Single-quote string context: 'payload'
		{Payload: baseFn, Prefix: "'+", Suffix: "+'", Description: "single-quote context time-based injection"},
		// Double-quote string context: "payload"
		{Payload: baseFn, Prefix: "\"+", Suffix: "+\"", Description: "double-quote context time-based injection"},
	}
}

// NodeJSTimePayload represents a time-based detection payload.
type NodeJSTimePayload struct {
	Payload     string
	Prefix      string
	Suffix      string
	Description string
}

// Time delays for 5-level confirmation (in milliseconds)
var timeDelays = []int64{10000, 9500, 8000, 5000, 0}

// sendPayload sends a mutated request with the given payload value and returns the response and duration.
func sendPayload(ctx context.Context, ab *base.Apollo, req *http.Request, param *http.Parameter, value string) (*http.Response, int64, error) {
	parameter := http.Parameter{
		Position: param.Position,
		Key:      param.Key,
		Value:    value,
	}
	mutatedReq := req.Mutate(&parameter)
	before := time.Now().UnixMilli()
	res, err := ab.HTTPClient.Respond(ctx, mutatedReq)
	after := time.Now().UnixMilli()
	if err != nil {
		return nil, 0, err
	}
	duration := after - before
	return res, duration, nil
}

// testErrorBasedInjection performs error-based Node.js injection detection.
// It injects payloads that should trigger Node.js errors if evaluated.
func testErrorBasedInjection(ctx context.Context, ab *base.Apollo, flow *http.Flow, param http.Parameter) bool {
	// First, check if the baseline response already contains Node.js errors
	baselineReq := flow.Request.DeepClone()
	baselineRes, baselineErr := ab.HTTPClient.Respond(ctx, baselineReq)
	if baselineErr == nil && baselineRes != nil {
		if found, _ := checkNodeJSErrors(baselineRes.Text); found {
			return false // Already has errors in baseline
		}
	}

	payloads := genErrorPayloads()
	for _, payload := range payloads {
		res, _, err := sendPayload(ctx, ab, flow.Request, &param, payload.Payload)
		if err != nil {
			continue
		}

		// Skip non-2xx/3xx responses
		if res.StatusCode < 200 || res.StatusCode >= 400 {
			continue
		}

		// Check for Node.js error patterns in the response
		if found, matchedText := checkNodeJSErrors(res.Text); found {
			// Baseline check: error should not appear in baseline response
			if baselineErr == nil && baselineRes != nil {
				if baselineFound, _ := checkNodeJSErrors(baselineRes.Text); baselineFound {
					continue
				}
			}

			// Report vulnerability
			parameter := http.Parameter{
				Position: param.Position,
				Key:      param.Key,
				Value:    payload.Payload,
			}
			v := ab.NewWebVuln(flow.Request.Mutate(&parameter), res, &parameter)
			if v != nil {
				v.SetTargetURL(flow.Request.URL())
				v.Payload = payload.Payload
				v.Add("parameter", param.Key)
				v.Add("detection_type", "error-based")
				v.Add("payload_description", payload.Description)
				v.Add("matched_error", matchedText)
				ab.OutputVuln(v)
				return true
			}
		}
	}
	return false
}

// testTimeBasedInjection performs time-based Node.js injection detection
// using 5-level sleep confirmation (10s, 9.5s, 8s, 5s, 0s).
func testTimeBasedInjection(ctx context.Context, ab *base.Apollo, flow *http.Flow, param http.Parameter) bool {
	timePayloads := genTimePayloads()

	for _, tp := range timePayloads {
		if confirmTiming(ctx, ab, flow, param, tp) {
			// Report vulnerability
			lastPayload := tp.Prefix + strings.Replace(tp.Payload, "{sleep}", fmt.Sprintf("%d", timeDelays[0]), 1) + tp.Suffix
			parameter := http.Parameter{
				Position: param.Position,
				Key:      param.Key,
				Value:    lastPayload,
			}
			mutatedReq := flow.Request.Mutate(&parameter)
			res, err := ab.HTTPClient.Respond(ctx, mutatedReq)
			if err != nil {
				continue
			}
			v := ab.NewWebVuln(mutatedReq, res, &parameter)
			if v != nil {
				v.SetTargetURL(flow.Request.URL())
				v.Payload = lastPayload
				v.Add("parameter", param.Key)
				v.Add("detection_type", "time-based")
				v.Add("payload_description", tp.Description)
				ab.OutputVuln(v)
				return true
			}
		}
	}
	return false
}

// confirmTiming performs 5-level time confirmation for a single timing payload.
// It tests multiple sleep durations and verifies the response time correlates
// with the injected sleep value, confirming code execution.
func confirmTiming(ctx context.Context, ab *base.Apollo, flow *http.Flow, param http.Parameter, tp NodeJSTimePayload) bool {
	// Test sequence: veryLongSleep(10s), noSleep(0), longSleep(8s), shortSleep(5s), longerSleep(9.5s)
	// Each step validates that timing correlates with the sleep value.

	// [#1] Very long sleep (10s)
	veryLongPayload := tp.Prefix + strings.Replace(tp.Payload, "{sleep}", fmt.Sprintf("%d", timeDelays[0]), 1) + tp.Suffix
	_, veryLongDuration, err := sendPayload(ctx, ab, flow.Request, &param, veryLongPayload)
	if err != nil {
		return false
	}
	// Response must take at least 99% of the sleep time
	if veryLongDuration < timeDelays[0]*99/100 {
		return false
	}

	// [#2] No sleep (0)
	noSleepPayload := tp.Prefix + strings.Replace(tp.Payload, "{sleep}", "0", 1) + tp.Suffix
	_, noSleepDuration, err := sendPayload(ctx, ab, flow.Request, &param, noSleepPayload)
	if err != nil {
		return false
	}
	// No-sleep response should be less than shortSleep (5s)
	if noSleepDuration >= timeDelays[3] {
		return false
	}
	// No-sleep duration should not exceed very-long duration
	if noSleepDuration > veryLongDuration {
		return false
	}

	// [#3] Long sleep (8s)
	longPayload := tp.Prefix + strings.Replace(tp.Payload, "{sleep}", fmt.Sprintf("%d", timeDelays[2]), 1) + tp.Suffix
	_, longDuration, err := sendPayload(ctx, ab, flow.Request, &param, longPayload)
	if err != nil {
		return false
	}
	if longDuration < timeDelays[2]*99/100 {
		return false
	}
	if noSleepDuration > longDuration {
		return false
	}
	if longDuration > veryLongDuration {
		return false
	}

	// [#4] Short sleep (5s)
	shortPayload := tp.Prefix + strings.Replace(tp.Payload, "{sleep}", fmt.Sprintf("%d", timeDelays[3]), 1) + tp.Suffix
	_, shortDuration, err := sendPayload(ctx, ab, flow.Request, &param, shortPayload)
	if err != nil {
		return false
	}
	if shortDuration < timeDelays[3]*99/100 {
		return false
	}
	// Short duration should be less than ~55% of long duration
	if shortDuration >= int64(float64(longDuration)*0.55) {
		return false
	}
	if shortDuration > longDuration {
		return false
	}

	// [#5] Longer sleep (9.5s)
	longerPayload := tp.Prefix + strings.Replace(tp.Payload, "{sleep}", fmt.Sprintf("%d", timeDelays[1]), 1) + tp.Suffix
	_, longerDuration, err := sendPayload(ctx, ab, flow.Request, &param, longerPayload)
	if err != nil {
		return false
	}
	if longerDuration < timeDelays[1]*99/100 {
		return false
	}
	if longerDuration < longDuration {
		return false
	}
	if shortDuration > longerDuration {
		return false
	}

	// All 5 timing checks passed - confirmed Node.js injection
	return true
}

// execAction performs Node.js injection detection using both
// error-based and time-based techniques.
func (p *NodeJSInject) execAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	logger.Debugf("Start detecting NodeJSInjection vulnerability URL=%s", flow.Request.URL().String())

	// Check if the server appears to be Node.js (optional gate)
	// We still test even if not detected via headers, as headers may be stripped
	isNode := false
	baselineReq := flow.Request.DeepClone()
	baselineRes, baselineErr := ab.HTTPClient.Respond(ctx, baselineReq)
	if baselineErr == nil && baselineRes != nil {
		isNode = isNodeJSServer(baselineRes)
	}

	// If the baseline response already contains Node.js errors, skip error-based testing
	searchForErrors := true
	if baselineErr == nil && baselineRes != nil {
		if found, _ := checkNodeJSErrors(baselineRes.Text); found {
			searchForErrors = false
		}
		// Skip if response body is too large (> 250KB as per AWVS)
		if len(baselineRes.Text) > 250*1024 {
			searchForErrors = false
		}
	}

	for _, param := range flow.Request.ParamsAll() {
		if param.Value == "" {
			continue
		}
		if strings.ToLower(param.Key) == "submit" {
			continue
		}

		// Step 1: Error-based detection (if applicable)
		if searchForErrors {
			if testErrorBasedInjection(ctx, ab, flow, param) {
				// Found via error-based detection, move to next parameter
				continue
			}
		}

		// Step 2: Time-based detection
		// Only run time-based detection if the server appears to be Node.js
		// or if we want to test regardless (headers may be stripped)
		if isNode {
			if testTimeBasedInjection(ctx, ab, flow, param) {
				continue
			}
		}
	}

	return nil
}
