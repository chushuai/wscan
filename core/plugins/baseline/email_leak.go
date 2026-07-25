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

type emailLeak struct{}

// Email regex pattern - matches common email formats
// Excludes common false positives like version strings (e.g., "1.0.0")
var emailRegex = regexp.MustCompile(`(?i)\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`)

// Common non-email patterns that look like emails
var falsePositiveEmailRegex = regexp.MustCompile(`(?i)^\d+\.\d+\.\d+$|^[a-f0-9]{8}-[a-f0-9]{4}-|^\$\{.*\}$|^0x[0-9a-f]+$`)

// Common internal/example email domains to filter out
var internalDomains = map[string]bool{
	"example.com":    true,
	"test.com":       true,
	"localhost":      true,
	"yourdomain.com": true,
	"domain.com":     true,
	"email.com":      true,
	"company.com":    true,
	"yoursite.com":   true,
}

func (d *emailLeak) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			// Skip non-text responses
			if flow.Response.IsJavaScript() || flow.Response.IsCss() || flow.Response.IsImage() {
				return nil
			}

			body := flow.Response.Text
			matches := emailRegex.FindAllString(body, -1)
			if len(matches) == 0 {
				return nil
			}

			// Filter out false positives and internal/example domains
			validEmails := []string{}
			for _, m := range matches {
				// Skip very short matches (likely false positives)
				if len(m) < 6 {
					continue
				}

				// Extract domain part
				atIndex := -1
				for i, c := range m {
					if c == '@' {
						atIndex = i
						break
					}
				}
				if atIndex < 0 || atIndex >= len(m)-1 {
					continue
				}

				domain := m[atIndex+1:]
				if internalDomains[domain] {
					continue
				}

				// Skip if the local part looks like a version string
				localPart := m[:atIndex]
				if falsePositiveEmailRegex.MatchString(localPart) {
					continue
				}

				validEmails = append(validEmails, m)
			}

			if len(validEmails) > 0 {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "email-leak: " + validEmails[0]
					a.OutputVuln(v)
				}
			}

			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/sensitive/email-leak",
			Plugin:   "baseline/sensitive/email-leak",
			Category: "baseline/sensitive/email-leak",
			Severity: model.SeverityLow,
		},
	}
}
