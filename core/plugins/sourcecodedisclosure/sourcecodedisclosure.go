/**
* @Author: shaochuyu
* @Date: 6/16/2026
 */
package sourcecodedisclosure

import (
	"context"
	"path"
	"strings"

	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// Config holds the plugin configuration.
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// SourceCodeDisclosure is the plugin struct for source code leak detection.
type SourceCodeDisclosure struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Close shuts down the plugin.
func (*SourceCodeDisclosure) Close() error {
	return nil
}

// DefaultConfig returns the default plugin configuration.
func (*SourceCodeDisclosure) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "source-code-disclosure",
			Enabled: true,
		},
	}
}

// Fingers returns the detection fingers for the plugin.
func (p *SourceCodeDisclosure) Fingers() []*base.Finger {
	return []*base.Finger{
		{
			CheckAction: p.checkAction,
			ExecAction:  p.execAction,
			Channel:     "web-generic",
			Binding: &model.VulnBinding{
				ID:       "source-code-disclosure/default",
				Plugin:   "source-code-disclosure",
				Category: "source-code-disclosure",
				Severity: model.SeverityHigh,
			},
		},
	}
}

// GetConfig returns the current plugin configuration.
func (p *SourceCodeDisclosure) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin.
func (p *SourceCodeDisclosure) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("SourceCodeDisclosure init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// checkAction verifies that the flow has parameters to test and
// the original response is not a binary type (image, CSS, JS).
func (p *SourceCodeDisclosure) checkAction(ctx context.Context, a *base.Apollo) error {
	flow := a.GetTargetFlow()

	// Skip flows without query or body parameters
	params := flow.Request.ParamsQueryAndBody()
	if len(params) == 0 {
		return errSkipNoParams
	}

	// Skip non-HTML/text responses (images, CSS, JS binaries)
	if flow.Response != nil {
		ct := flow.Response.GetContentType()
		if isBinaryContentType(ct) {
			return errSkipBinaryResponse
		}
	}

	return nil
}

// execAction injects source code leak triggers into each parameter and
// checks the response for source code signatures.
func (p *SourceCodeDisclosure) execAction(ctx context.Context, a *base.Apollo) error {
	flow := a.GetTargetFlow()
	logger.Debugf("Start detection source-code-disclosure, URL=%s", flow.Request.URL().String())

	// Get baseline response for anti-false-positive comparison
	baselineReq := flow.Request.DeepClone()
	baselineRes, baselineErr := a.HTTPClient.Respond(ctx, baselineReq)

	// Extract current filename from the URL path
	urlPath := flow.Request.URL().Path
	filename := path.Base(urlPath)
	if filename == "" || filename == "/" || filename == "." {
		return nil
	}

	params := flow.Request.ParamsQueryAndBody()
	for _, param := range params {
		if param.Position == http.PositionHeader || param.Position == http.PositionCookie {
			continue
		}

		for _, payload := range buildPayloads(param.Value, filename) {
			parameter := http.Parameter{
				Position: param.Position,
				Key:      param.Key,
				Value:    payload.value,
				Suffix:   payload.suffix,
			}

			req := flow.Request.Mutate(&parameter)
			res, err := a.HTTPClient.Respond(ctx, req)
			if err != nil {
				continue
			}

			// Only check successful responses
			if res.StatusCode < 200 || res.StatusCode >= 400 {
				continue
			}

			// Skip binary responses
			ct := res.GetContentType()
			if isBinaryContentType(ct) {
				continue
			}

			// Check for source code signatures in the response
			signature := findSourceCodeSignature(res.Text)
			if signature == "" {
				continue
			}

			// Anti-false-positive: check if the baseline response also contains
			// the same signature (present before injection → not caused by our payload)
			if baselineErr == nil && baselineRes != nil {
				if findSourceCodeSignature(baselineRes.Text) != "" {
					continue
				}
			}

			// Anti-false-positive: send a "padded" variant of the filename.
			// If source code signatures disappear in the padded response, the leak
			// is confirmed; if they still appear, it was a false positive.
			paddingValue := "padding" + filename
			paddingPayload := buildPaddingPayload(param.Value, paddingValue, payload.kind)
			if paddingPayload != "" {
				padParameter := http.Parameter{
					Position: param.Position,
					Key:      param.Key,
					Value:    paddingPayload,
				}
				padReq := flow.Request.Mutate(&padParameter)
				padRes, padErr := a.HTTPClient.Respond(ctx, padReq)
				if padErr == nil && padRes != nil {
					if findSourceCodeSignature(padRes.Text) != "" {
						// Signature still present with padded filename → false positive
						continue
					}
				}
			}

			// Leak confirmed — report the vulnerability
			v := a.NewWebVuln(req, res, &parameter)
			if v != nil {
				v.SetTargetURL(flow.Request.URL())
				v.Payload = payload.description
				v.Extra["signature"] = signature
				v.Extra["payload_kind"] = payload.kind
				v.Extra["parameter"] = param.Key
				a.OutputVuln(v)
			}
			// One confirmed finding per parameter is enough
			break
		}
	}

	return nil
}

// ============================================================================
// Payload generation
// ============================================================================

// payload represents an injection payload with metadata.
type payload struct {
	value       string // The parameter value to set
	suffix      string // Suffix to append (for Mutate Suffix mode)
	kind        string // Type of injection (null-byte, dot-slash, ush-it)
	description string // Human-readable description for the vuln report
}

// buildPayloads generates source code leak trigger payloads for a parameter.
func buildPayloads(paramValue, filename string) []payload {
	var payloads []payload

	// a) Null byte injection: param_value%00
	payloads = append(payloads, payload{
		value:       paramValue,
		suffix:      "%00",
		kind:        "null-byte",
		description: "null byte injection: " + paramValue + "%00",
	})

	// b) Dot-slash trick: param_value/.
	payloads = append(payloads, payload{
		value:       paramValue,
		suffix:      "/.",
		kind:        "dot-slash",
		description: "dot-slash trick: " + paramValue + "/.",
	})

	// c) ush.it trick: inject path traversal that triggers source disclosure
	// The ush.it technique appends the filename with path traversal components
	// that cause some servers to serve the source instead of executing it.
	ushPayload := paramValue + "/." + filename + "/." + filename
	payloads = append(payloads, payload{
		value:       ushPayload,
		kind:        "ush-it",
		description: "ush.it path disclosure: " + ushPayload,
	})

	return payloads
}

// buildPaddingPayload constructs the "padded" filename variant for
// anti-false-positive verification. The padding prefix makes the
// filename different enough that real source disclosure should not trigger.
func buildPaddingPayload(paramValue, paddingFilename, kind string) string {
	switch kind {
	case "null-byte":
		return paramValue + "padding%00"
	case "dot-slash":
		return paramValue + "/."
	case "ush-it":
		return paramValue + "/." + paddingFilename + "/." + paddingFilename
	default:
		return ""
	}
}

// ============================================================================
// Source code signature detection
// ============================================================================

// sourceCodeSignature defines a pattern that indicates leaked source code.
type sourceCodeSignature struct {
	pattern  string
	language string
}

// sourceCodeSignatures lists the signatures to search for in response bodies.
// Order matters: more specific patterns should come first to be reported.
var sourceCodeSignatures = []sourceCodeSignature{
	// PHP
	{pattern: "<?php", language: "PHP"},
	{pattern: "<?=", language: "PHP"},

	// ASP
	{pattern: "<%@", language: "ASP"},
	{pattern: "<%", language: "ASP"},
	{pattern: "Runat=\"server\"", language: "ASP"},

	// Python
	{pattern: "#!/usr/bin/python", language: "Python"},
	{pattern: "#!/usr/bin/env python", language: "Python"},
	{pattern: "import ", language: "Python"},
	{pattern: "def ", language: "Python"},
	{pattern: "from ", language: "Python"},

	// Perl
	{pattern: "#!/usr/bin/perl", language: "Perl"},
	{pattern: "use strict", language: "Perl"},

	// C#
	{pattern: "using System", language: "C#"},
	{pattern: "namespace ", language: "C#"},

	// Ruby
	{pattern: "#!/usr/bin/ruby", language: "Ruby"},
	{pattern: "require '", language: "Ruby"},

	// Java
	{pattern: "import java.", language: "Java"},
	{pattern: "public class", language: "Java"},
}

// findSourceCodeSignature checks the response body for source code signatures.
// Returns the first matching language+pattern string, or empty string if none found.
func findSourceCodeSignature(body string) string {
	if body == "" {
		return ""
	}
	for _, sig := range sourceCodeSignatures {
		if strings.Contains(body, sig.pattern) {
			return sig.language + ": " + sig.pattern
		}
	}
	return ""
}

// ============================================================================
// Content type helpers
// ============================================================================

// binaryContentPrefixes lists content type prefixes that indicate binary
// responses which should not be checked for source code signatures.
var binaryContentPrefixes = []string{
	"image/",
	"audio/",
	"video/",
	"application/octet-stream",
	"application/pdf",
	"application/zip",
	"application/gzip",
	"application/x-tar",
	"application/x-rar",
	"application/x-7z",
	"font/",
	"application/font",
}

// binaryContentTypes lists exact content types that are binary.
var binaryContentTypes = map[string]bool{
	"text/css":                 true,
	"application/javascript":   true,
	"application/x-javascript": true,
}

// isBinaryContentType returns true if the content type indicates a binary or
// non-HTML response that should be skipped for source code leak detection.
func isBinaryContentType(ct string) bool {
	if ct == "" {
		return false
	}
	lower := strings.ToLower(ct)
	// Strip charset etc. after semicolon
	if idx := strings.Index(lower, ";"); idx >= 0 {
		lower = strings.TrimSpace(lower[:idx])
	}
	if binaryContentTypes[lower] {
		return true
	}
	for _, prefix := range binaryContentPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// ============================================================================
// Sentinel errors for CheckAction skipping
// ============================================================================

var (
	errSkipNoParams       = &skipError{msg: "no query or body parameters to test"}
	errSkipBinaryResponse = &skipError{msg: "response is binary content type"}
)

type skipError struct {
	msg string
}

func (e *skipError) Error() string {
	return e.msg
}
