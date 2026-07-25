/**
* @Author: wscan
* @Date: 2026/06/16
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
	"wscan/core/plugins/helper/knowledge"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

// debugModeKey returns the KDB key used for deduplication per debug mode type and target host.
func debugModeKey(debugType string, host string) string {
	return fmt.Sprintf("baseline/debug-mode/%s/%s", debugType, host)
}

// isDebugModeAlreadyReported checks KDB whether this debug mode type
// has already been reported for the given target host in this scan.
func isDebugModeAlreadyReported(a *base.Apollo, debugType string, host string) bool {
	if a.KDB == nil {
		return false
	}
	key := debugModeKey(debugType, host)
	item := a.KDB.Get(key)
	if item != nil && item.Exist("reported") {
		return true
	}
	return false
}

// markDebugModeReported marks this debug mode type as already reported for the given host.
func markDebugModeReported(a *base.Apollo, debugType string, host string) {
	if a.KDB == nil {
		return
	}
	key := debugModeKey(debugType, host)
	item := a.KDB.Get(key)
	if item == nil {
		item = knowledge.NewKBItem()
		a.KDB.Save(key, item)
	}
	item.Set("reported", true)
}

// extractHost extracts the host (hostname:port) from a URL string.
func extractHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Host
}

// flaskDebugModeChecker detects Flask/Werkzeug debug mode.
type flaskDebugModeChecker struct{}

func (d *flaskDebugModeChecker) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("Start detecting Flask debug mode, URL=%s", flow.Request.URL().String())

			// Skip non-text responses
			if flow.Response.IsJavaScript() || flow.Response.IsCss() || flow.Response.IsImage() {
				return nil
			}

			host := extractHost(flow.Request.URL().String())

			// Global dedup: only report once per target
			if isDebugModeAlreadyReported(a, "flask-debug", host) {
				return nil
			}

			// Send request with Werkzeug debugger query parameters
			debugURL := flow.Request.URL().String()
			if strings.Contains(debugURL, "?") {
				debugURL += "&__debugger__=yes&cmd=resource&f=debugger.js"
			} else {
				debugURL += "?__debugger__=yes&cmd=resource&f=debugger.js"
			}

			debugReq, err := http.NewRequest("GET", debugURL, nil)
			if err != nil {
				return nil
			}

			resp, err := a.HTTPClient.Respond(ctx, debugReq)
			if err != nil {
				return nil
			}

			body := resp.Text
			// Check for Werkzeug debugger features - require at least 2 indicators
			indicators := []string{
				"Werkzeug debugger",
				"PIN",
				"__debugger__",
				"traceback",
				"console",
			}
			matchCount := 0
			for _, indicator := range indicators {
				if strings.Contains(body, indicator) {
					matchCount++
				}
			}

			if matchCount >= 2 {
				markDebugModeReported(a, "flask-debug", host)
				v := a.NewWebVuln(debugReq, resp, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "?__debugger__=yes&cmd=resource&f=debugger.js"
					a.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/config/flask-debug-mode",
			Plugin:   "baseline/config/flask-debug-mode",
			Category: "baseline/config/debug-mode",
			Severity: model.SeverityMedium,
		},
	}
}

// djangoDebugModeChecker detects Django debug mode via invalid Host header.
type djangoDebugModeChecker struct{}

func (d *djangoDebugModeChecker) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("Start detecting Django debug mode, URL=%s", flow.Request.URL().String())

			// Skip non-text responses
			if flow.Response.IsJavaScript() || flow.Response.IsCss() || flow.Response.IsImage() {
				return nil
			}

			host := extractHost(flow.Request.URL().String())

			// Global dedup: only report once per target
			if isDebugModeAlreadyReported(a, "django-debug", host) {
				return nil
			}

			// Send request with invalid Host header to trigger DisallowedHost
			invalidHost := "SomeInvalidHost12345"
			modifiedReq := flow.Request.Mutate(&http.Parameter{
				Position: http.PositionHeader,
				Key:      "Host",
				Value:    invalidHost,
			})
			if modifiedReq == nil {
				return nil
			}

			resp, err := a.HTTPClient.Respond(ctx, modifiedReq)
			if err != nil {
				return nil
			}

			body := resp.Text
			// Check for Django debug page indicators
			isDjangoDebug := false
			if strings.Contains(body, "DisallowedHost") ||
				strings.Contains(body, "DisallowedHost at") ||
				strings.Contains(body, "You're seeing this error because you have DEBUG = True") ||
				(strings.Contains(body, "Django") && strings.Contains(body, "Traceback")) {
				isDjangoDebug = true
			}

			if isDjangoDebug {
				markDebugModeReported(a, "django-debug", host)
				v := a.NewWebVuln(modifiedReq, resp, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = fmt.Sprintf("Host: %s", invalidHost)
					a.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/config/django-debug-mode",
			Plugin:   "baseline/config/django-debug-mode",
			Category: "baseline/config/debug-mode",
			Severity: model.SeverityMedium,
		},
	}
}

// pythonTracebackChecker detects Python framework debug mode via traceback on 404.
// Covers Tornado, Pyramid, and other Python frameworks that show tracebacks.
type pythonTracebackChecker struct{}

func (d *pythonTracebackChecker) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("Start detecting Python traceback debug mode, URL=%s", flow.Request.URL().String())

			// Skip non-text responses
			if flow.Response.IsJavaScript() || flow.Response.IsCss() || flow.Response.IsImage() {
				return nil
			}

			host := extractHost(flow.Request.URL().String())

			// Global dedup: only report once per target
			if isDebugModeAlreadyReported(a, "python-traceback", host) {
				return nil
			}

			// Request a random non-existent path to trigger 404 with traceback
			randomPath := fmt.Sprintf("/%s_%s_nonexistent_debug_check", utils.RandLetters(6), utils.RandLowLetterNumber(4))
			reqURL := flow.Request.URL()
			// Build a new URL with the random path
			newURL := fmt.Sprintf("%s://%s%s", reqURL.Scheme, reqURL.Host, randomPath)

			debugReq, err := http.NewRequest("GET", newURL, nil)
			if err != nil {
				return nil
			}

			resp, err := a.HTTPClient.Respond(ctx, debugReq)
			if err != nil {
				return nil
			}

			body := resp.Text
			// Check for Python traceback in response
			if strings.Contains(body, "Traceback (most recent call last):") {
				markDebugModeReported(a, "python-traceback", host)
				v := a.NewWebVuln(debugReq, resp, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = randomPath
					a.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/config/python-traceback-debug",
			Plugin:   "baseline/config/python-traceback-debug",
			Category: "baseline/config/debug-mode",
			Severity: model.SeverityLow,
		},
	}
}

// railsDebugModeChecker detects Rails development/debug mode.
type railsDebugModeChecker struct{}

func (d *railsDebugModeChecker) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("Start detecting Rails debug mode, URL=%s", flow.Request.URL().String())

			// Skip non-text responses
			if flow.Response.IsJavaScript() || flow.Response.IsCss() || flow.Response.IsImage() {
				return nil
			}

			host := extractHost(flow.Request.URL().String())

			// Global dedup: only report once per target
			if isDebugModeAlreadyReported(a, "rails-debug", host) {
				return nil
			}

			body := flow.Response.Text
			isRailsDebug := false

			// Check response headers for Rails-specific debug info
			xRackCache := flow.Response.GetHeader("X-Rack-Cache")
			xRuntime := flow.Response.GetHeader("X-Runtime")

			// Both X-Rack-Cache and X-Runtime are strong indicators of Rails development mode
			if xRackCache != "" && xRuntime != "" {
				// Check body for additional Rails debug indicators
				railsBodyIndicators := []string{
					"Rails",
					"ActionController",
					"ActiveRecord",
					"config/routes.rb",
					"development.log",
				}
				for _, indicator := range railsBodyIndicators {
					if strings.Contains(body, indicator) {
						isRailsDebug = true
						break
					}
				}

				// Even without body indicators, presence of both headers suggests Rails in dev mode
				if !isRailsDebug {
					isRailsDebug = true
				}
			}

			// Also check for Rails debug page in body
			if !isRailsDebug {
				railsDebugPageIndicators := []string{
					"Rails.root",
					"Action Dispatch",
					"Showing /app",
				}
				for _, indicator := range railsDebugPageIndicators {
					if strings.Contains(body, indicator) {
						isRailsDebug = true
						break
					}
				}
			}

			if isRailsDebug {
				markDebugModeReported(a, "rails-debug", host)
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "X-Rack-Cache + X-Runtime headers / Rails debug page"
					a.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/config/rails-debug-mode",
			Plugin:   "baseline/config/rails-debug-mode",
			Category: "baseline/config/debug-mode",
			Severity: model.SeverityLow,
		},
	}
}
