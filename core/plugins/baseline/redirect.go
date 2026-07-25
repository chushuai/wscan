/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package baseline

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

type redirectLogic struct{}

func (d *redirectLogic) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("Start detecting open redirect, URL=%s", flow.Request.URL().String())

			// Generate a random external domain as the redirect target
			randomDomain := fmt.Sprintf("%s.com", utils.RandLetters(6))
			randomInt := utils.RandInt(10000000, 100000000)

			// Payload list for redirect testing
			payloads := []struct {
				Value   string
				IsValue bool
			}{
				{Value: randomDomain, IsValue: true},
				{Value: fmt.Sprintf("https://evil%s.com", utils.RandLetters(4)), IsValue: true},
				{Value: fmt.Sprintf("//%s", randomDomain), IsValue: true},
				{Value: fmt.Sprintf("https:////%s", randomDomain), IsValue: true},
				{Value: fmt.Sprintf("/\\%s", randomDomain), IsValue: true},
				{Value: fmt.Sprintf("/%s/", randomDomain), IsValue: true},
				{Value: fmt.Sprintf("https://trusted.com@%s", randomDomain), IsValue: true},
				{Value: fmt.Sprintf("https://%d.example.com", randomInt), IsValue: true},
			}

			// Iterate over all request parameters
			for _, param := range flow.Request.ParamsAll() {
				if !isRedirectParam(param) {
					continue
				}
				for _, p := range payloads {
					var req *http.Request
					if p.IsValue {
						req = flow.Request.Mutate(&http.Parameter{
							Position: param.Position,
							Key:      param.Key,
							Value:    p.Value,
						})
					} else {
						req = flow.Request.Mutate(&http.Parameter{
							Position: param.Position,
							Key:      param.Key,
							Value:    param.Value,
							Suffix:   p.Value,
						})
					}
					if req == nil {
						continue
					}

					res, err := a.HTTPClient.Respond(ctx, req)
					if err != nil {
						continue
					}

					// Check for 3xx redirect with Location header pointing to our payload
					if res.StatusCode > 300 && res.StatusCode < 400 {
						location := res.GetHeader(http.LOCATION)
						if location != "" && isRedirectToPayload(location, p.Value) {
							v := a.NewWebVuln(req, res, &param)
							if v != nil {
								v.SetTargetURL(flow.Request.URL())
								v.Payload = p.Value
								a.OutputVuln(v)
							}
							return nil
						}
					}
				}
			}

			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/injection/open-redirect",
			Plugin:   "baseline/injection/open-redirect",
			Category: "baseline/injection/open-redirect",
			Severity: model.SeverityMedium,
		},
	}
}

// isRedirectParam checks if a parameter might be used for redirects
func isRedirectParam(param http.Parameter) bool {
	if strings.HasPrefix(param.Value, "http") {
		return true
	}
	if strings.HasPrefix(param.Value, "//") {
		return true
	}
	if strings.HasPrefix(param.Value, "/") && len(param.Value) > 1 {
		return true
	}
	paramNameLower := strings.ToLower(param.Key)
	redirectKeywords := []string{"url", "redirect", "redir", "return", "next", "goto", "link", "target", "destination", "continue", "forward"}
	for _, kw := range redirectKeywords {
		if strings.Contains(paramNameLower, kw) {
			return true
		}
	}
	return false
}

// isRedirectToPayload verifies that the Location header points to the payload target
func isRedirectToPayload(location, payload string) bool {
	if strings.Contains(location, payload) {
		return true
	}
	locURL, err := url.Parse(location)
	if err != nil {
		return strings.Contains(location, payload)
	}
	payloadURL, err := url.Parse(payload)
	if err != nil {
		return strings.Contains(location, payload)
	}
	if payloadURL.Host != "" {
		return locURL.Host == payloadURL.Host || strings.HasSuffix(locURL.Host, payloadURL.Host)
	}
	return strings.Contains(locURL.Host, payload) || strings.Contains(locURL.String(), payload)
}
