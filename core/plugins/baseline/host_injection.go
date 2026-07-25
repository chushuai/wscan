/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package baseline

import (
	"context"
	"fmt"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

type hostInjection struct{}

func (d *hostInjection) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("Start detecting Host header injection, URL=%s", flow.Request.URL().String())

			// Skip non-text responses
			if flow.Response.IsJavaScript() || flow.Response.IsCss() || flow.Response.IsImage() {
				return nil
			}

			originalHost := flow.Request.Host
			if originalHost == "" {
				return nil
			}

			// Generate a random injection payload
			randomPrefix := utils.RandLetters(8)
			injectedHost := fmt.Sprintf("%s.%s", randomPrefix, originalHost)

			// Clone the request and modify the Host header
			modifiedReq := flow.Request.Mutate(&http.Parameter{
				Position: http.PositionHeader,
				Key:      "Host",
				Value:    injectedHost,
			})
			if modifiedReq == nil {
				return nil
			}

			// Send the modified request
			resp, err := a.HTTPClient.Respond(ctx, modifiedReq)
			if err != nil {
				return nil
			}

			// Check if the injected host is reflected in the response body
			if strings.Contains(resp.Text, injectedHost) || strings.Contains(resp.Text, randomPrefix) {
				v := a.NewWebVuln(modifiedReq, resp, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = injectedHost
					a.OutputVuln(v)
				}
				return nil
			}

			// Check if the injected host is used in a redirect
			if resp.StatusCode > 300 && resp.StatusCode < 400 {
				location := resp.GetHeader("Location")
				if location != "" && (strings.Contains(location, injectedHost) || strings.Contains(location, randomPrefix)) {
					v := a.NewWebVuln(modifiedReq, resp, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = injectedHost
						a.OutputVuln(v)
					}
				}
			}

			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/injection/host-injection",
			Plugin:   "baseline/injection/host-injection",
			Category: "baseline/injection/host-injection",
			Severity: model.SeverityMedium,
		},
	}
}
