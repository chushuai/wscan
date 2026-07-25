/**
* @Author: shaochuyu
* @Date: 6/16/2026 10:00
 */
package esiinject

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/reverse"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

type ESIInject struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

// BaseConfig returns the base config, fixed format, no modification needed
func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// Close closes the plugin
func (*ESIInject) Close() error {
	return nil
}

// DefaultConfig returns the default configuration
func (*ESIInject) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "esi-inject",
		Enabled: true,
	}}
	return config
}

// Fingers returns the vulnerability detection configuration
func (p *ESIInject) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: p.checkAction,
		ExecAction:  p.execAction,
		NeedReverse: true,
		Channel:     "website",
		Binding:     &model.VulnBinding{ID: "esi_injection", Plugin: "esi-inject", Category: "esi-inject", Severity: model.SeverityHigh},
	})
	return fingers
}

// GetConfig returns the configuration
func (p *ESIInject) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin
func (p *ESIInject) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("ESIInject init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// isHTMLContentType checks if the Content-Type indicates HTML content
func isHTMLContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "application/xhtml") ||
		strings.Contains(ct, "text/xhtml")
}

// checkAction checks if the response has HTML content type and request has parameters
func (p *ESIInject) checkAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()

	// Skip non-HTML responses
	if flow.Response != nil {
		ct := flow.Response.Header.Get("Content-Type")
		if ct == "" {
			ct = flow.Request.ContentType()
		}
		if !isHTMLContentType(ct) {
			return fmt.Errorf("response is not HTML content type")
		}
	}

	// Check that there are parameters with values
	for _, param := range flow.Request.ParamsAll() {
		if param.Value != "" {
			return nil
		}
	}
	return fmt.Errorf("no parameters with values found")
}

// esiPayload represents an ESI injection test payload
type esiPayload struct {
	payload      string // the ESI injection payload string
	urlEncoded   string // URL-encoded variant of the payload
	token        string // unique token for verification
	verifyMarker string // SHA1 hash of the token as verification marker
}

// generateESIPayloads generates ESI injection test payloads using the reverse platform
func generateESIPayloads(reverseURL string) []esiPayload {
	token := utils.RandLowLetterNumber(8)
	verifyMarker := utils.CalcSha1(token)

	// Standard ESI include payload
	payload := fmt.Sprintf(`<esi:include src="%s/esi/%s"/>`, reverseURL, token)
	// URL-encoded variant
	urlEncoded := fmt.Sprintf(`%%3Cesi%%3Ainclude+src%%3D%%22%s%%2Fesi%%2F%s%%22%%2F%%3E`, reverseURL, token)

	return []esiPayload{
		{
			payload:      payload,
			urlEncoded:   urlEncoded,
			token:        token,
			verifyMarker: verifyMarker,
		},
	}
}

// reportVuln reports a detected ESI injection vulnerability
func reportVuln(ab *base.Apollo, flow *http.Flow, req *http.Request, res *http.Response, param *http.Parameter, payload string) {
	v := ab.NewWebVuln(req, res, &http.Parameter{
		Position: param.Position,
		Key:      param.Key,
		Value:    payload,
	})
	if v != nil {
		v.SetTargetURL(flow.Request.URL())
		v.Payload = payload
		ab.OutputVuln(v)
	}
}

// testESIPayload injects an ESI payload into a parameter and sends the request
func testESIPayload(ctx context.Context, ab *base.Apollo, req *http.Request, param *http.Parameter, payloadStr string) (*http.Request, *http.Response, error) {
	parameter := http.Parameter{
		Position: param.Position,
		Key:      param.Key,
		Value:    payloadStr,
	}
	mutatedReq := req.Mutate(&parameter)
	res, err := ab.HTTPClient.Respond(ctx, mutatedReq)
	if err != nil {
		logger.Error(err)
		return nil, nil, err
	}
	// Only check 2xx/3xx responses
	if res.StatusCode < 200 || res.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("non-success status code: %d", res.StatusCode)
	}
	return mutatedReq, res, nil
}

// isESIProcessed checks whether the ESI tag was actually processed by the server
// (not just reflected). If the server processes the ESI include, it will fetch
// the URL and the response will contain content from the reverse platform rather
// than the raw ESI tag. If the ESI tag is merely reflected, it will appear
// literally in the response.
func isESIProcessed(responseText string, esiPayload esiPayload) bool {
	// Check if the raw ESI tag is reflected (not processed)
	if strings.Contains(responseText, esiPayload.payload) {
		// The tag is reflected as-is, meaning the server did NOT process it
		// But we should still check if it was partially processed
		// Some ESI processors strip the tag but don't include content
		return false
	}
	// If the ESI tag is NOT in the response, it may have been processed
	// (the server replaced it with the included content)
	// Check for the verification marker in the response
	if strings.Contains(responseText, esiPayload.verifyMarker) {
		return true
	}
	return false
}

// execAction performs the ESI injection vulnerability detection
func (p *ESIInject) execAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	logger.Debugf("Start detecting ESIInjection vulnerability URL=%s", flow.Request.URL().String())

	for _, param := range flow.Request.ParamsAll() {
		if strings.ToLower(param.Key) == "submit" {
			continue
		}
		if param.Value == "" {
			continue
		}

		// Register a reverse unit for OOB detection
		unit := ab.Reverse.Register(nil)
		reverseURL := unit.GetVisitURL()
		// Strip the trailing slash for clean URL construction
		reverseURL = strings.TrimRight(reverseURL, "/")

		payloads := generateESIPayloads(reverseURL)

		for _, esiPayload := range payloads {
			// Test the standard ESI payload
			mutatedReq, res, err := testESIPayload(ctx, ab, flow.Request, &param, esiPayload.payload)
			if err != nil {
				continue
			}

			vulnDetected := false

			// Check if the ESI tag was processed in-band (server rendered the include)
			if isESIProcessed(res.Text, esiPayload) {
				reportVuln(ab, flow, mutatedReq, res, &param, esiPayload.payload)
				vulnDetected = true
			}

			// Test the URL-encoded variant
			encodedReq, encodedRes, err := testESIPayload(ctx, ab, flow.Request, &param, esiPayload.urlEncoded)
			if err == nil && !vulnDetected {
				if isESIProcessed(encodedRes.Text, esiPayload) {
					reportVuln(ab, flow, encodedReq, encodedRes, &param, esiPayload.urlEncoded)
					vulnDetected = true
				}
			}

			// Out-of-band detection via reverse platform HTTP callback
			if !vulnDetected {
				unit.OnVisit(func(event *reverse.Event) error {
					// OOB callback received - the server fetched the ESI include URL
					reportVuln(ab, flow, mutatedReq, res, &param, esiPayload.payload)
					return nil
				})
				unit.Fetch(0)
			}

			if vulnDetected {
				return nil
			}
		}
	}

	// Also test ESI injection in the request path for URLs with path segments
	// Some ESI processors may also process ESI tags in URL paths
	unit := ab.Reverse.Register(nil)
	reverseURL := strings.TrimRight(unit.GetVisitURL(), "/")
	token := utils.RandLowLetterNumber(8)
	pathPayload := fmt.Sprintf("<esi:include src=\"%s/esi/%s\"/>", reverseURL, token)

	// Test path injection
	req := flow.Request.DeepClone()
	parsedURL, _ := url.Parse(req.GetOriginURL())
	if parsedURL != nil {
		originalPath := parsedURL.Path
		parsedURL.Path = originalPath + pathPayload
		req.SetURL(parsedURL)

		res, err := ab.HTTPClient.Respond(ctx, req)
		if err == nil && res != nil && res.StatusCode >= 200 && res.StatusCode < 400 {
			verifyMarker := utils.CalcSha1(token)
			if strings.Contains(res.Text, verifyMarker) {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = pathPayload
					ab.OutputVuln(v)
				}
				return nil
			}

			// OOB detection for path injection
			unit.OnVisit(func(event *reverse.Event) error {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = pathPayload
					ab.OutputVuln(v)
				}
				return nil
			})
			unit.Fetch(0)
		}
	}

	return nil
}
