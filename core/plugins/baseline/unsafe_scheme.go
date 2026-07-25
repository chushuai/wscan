/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package baseline

import (
	"context"
	"regexp"
	"wscan/core/model"
	"wscan/core/plugins/base"
)

type unsafeSchemeLeak struct{}

// Pre-compiled regex for finding HTTP resources in HTML attributes
// Matches patterns like src="http://", href="http://", action="http://", url(http://), etc.
var unsafeSchemeRegex = regexp.MustCompile(`(?i)(?:src|href|action|data|background|poster|codebase|cite|longdesc|usemap|profile|for)\s*=\s*["']?\s*http://[^\s"'<>]+`)

// Also check for url() patterns in inline styles with http://
var unsafeSchemeStyleRegex = regexp.MustCompile(`(?i)url\s*\(\s*["']?\s*http://[^\s"'<>)]+\s*["']?\s*\)`)

// Form action with http:// on HTTPS page
var unsafeFormActionRegex = regexp.MustCompile(`(?i)<form[^>]+action\s*=\s*["']?\s*http://[^\s"'<>]+`)

func (d *unsafeSchemeLeak) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			// Skip non-HTML responses
			if !flow.Response.IsHTML() {
				return nil
			}

			// Only check on HTTPS pages
			if flow.Request.URL().Scheme != "https" {
				return nil
			}

			body := flow.Response.Text
			if body == "" {
				return nil
			}

			var foundItems []string

			// Check for HTTP resources in HTML attributes
			attrMatches := unsafeSchemeRegex.FindAllString(body, -1)
			foundItems = append(foundItems, attrMatches...)

			// Check for url() patterns in inline styles
			styleMatches := unsafeSchemeStyleRegex.FindAllString(body, -1)
			foundItems = append(foundItems, styleMatches...)

			// Check for form actions with http://
			formMatches := unsafeFormActionRegex.FindAllString(body, -1)
			foundItems = append(foundItems, formMatches...)

			if len(foundItems) > 0 {
				// Truncate payload for display
				payload := foundItems[0]
				if len(payload) > 200 {
					payload = payload[:200] + "..."
				}
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = payload
					a.OutputVuln(v)
				}
			}

			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/config/unsafe-scheme",
			Plugin:   "baseline/config/unsafe-scheme",
			Category: "baseline/config/unsafe-scheme",
			Severity: model.SeverityMedium,
		},
	}
}
