/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package baseline

import (
	"context"
	"regexp"
	"strings"
	"wscan/core/model"
	"wscan/core/plugins/base"
)

type htmlCommentLeak struct{}

// HTML comment regex: matches <!-- ... -->
var htmlCommentRegex = regexp.MustCompile(`<!--([\s\S]*?)-->`)

// Sensitive keywords that may appear in HTML comments
var sensitiveCommentKeywords = []string{
	// Debug/development markers
	"TODO", "FIXME", "HACK", "XXX", "BUG", "WORKAROUND", "DEPRECATED",
	// Credential hints
	"password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "api-key",
	"access_key", "accesskey", "private_key", "privatekey",
	"auth", "credential", "mysql", "postgres", "database", "db_pass",
	// Debug information
	"debug", "stacktrace", "traceback", "exception", "error_log",
	// Config hints
	"config", "setting", "env", "environment",
	// Internal URLs
	"internal", "staging", "production", "admin",
}

// Patterns that indicate sensitive data in comments
var sensitiveCommentPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|token|key|credential)\s*[:=]\s*\S+`),
	regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?key|private[_-]?key)\s*[:=]\s*\S+`),
	regexp.MustCompile(`(?i)(?:mysql|postgres|redis|mongodb)://\S+`),
	regexp.MustCompile(`(?i)jdbc:\S+`),
	regexp.MustCompile(`(?i)(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`), // AWS key patterns
	regexp.MustCompile(`(?i)-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----`),           // Private key headers
}

func (d *htmlCommentLeak) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			// Skip non-HTML responses
			if !flow.Response.IsHTML() {
				return nil
			}

			body := flow.Response.Text
			if body == "" {
				return nil
			}

			// Find all HTML comments
			comments := htmlCommentRegex.FindAllStringSubmatch(body, -1)
			if len(comments) == 0 {
				return nil
			}

			for _, comment := range comments {
				if len(comment) < 2 {
					continue
				}
				commentText := comment[1]
				commentText = strings.TrimSpace(commentText)

				// Skip empty or very short comments
				if len(commentText) < 3 {
					continue
				}

				// Skip conditional comments (IE)
				if strings.HasPrefix(commentText, "[if") || strings.HasPrefix(commentText, "[endif") {
					continue
				}

				// Check for sensitive patterns first (higher confidence)
				for _, pattern := range sensitiveCommentPatterns {
					if pattern.MatchString(commentText) {
						v := a.NewWebVuln(flow.Request, flow.Response, nil)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = "sensitive-html-comment: " + truncateString(commentText, 200)
							a.OutputVuln(v)
						}
						return nil
					}
				}

				// Check for sensitive keywords
				commentLower := strings.ToLower(commentText)
				for _, keyword := range sensitiveCommentKeywords {
					if strings.Contains(commentLower, strings.ToLower(keyword)) {
						v := a.NewWebVuln(flow.Request, flow.Response, nil)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = "sensitive-html-comment: " + truncateString(commentText, 200)
							a.OutputVuln(v)
						}
						return nil
					}
				}
			}

			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/sensitive/html-comment",
			Plugin:   "baseline/sensitive/html-comment",
			Category: "baseline/sensitive/html-comment",
			Severity: model.SeverityLow,
		},
	}
}
