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

type cookiePasswordLeak struct{}

// Password-like patterns in cookie values
var passwordPatterns = []*regexp.Regexp{
	// Looks like a plaintext password (mixed case + digits, length >= 6)
	regexp.MustCompile(`^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':",.<>\/?]{6,}$`),
}

// Cookie names that commonly contain password-like values
var passwordCookieNamePatterns = []string{
	"pass", "pwd", "password", "passwd", "secret", "token",
	"key", "auth", "credential", "private",
}

// Cookie names that are commonly used for non-password purposes and should be excluded
var excludeCookieNames = map[string]bool{
	"sessionid":       true,
	"jsessionid":      true,
	"phpsessid":       true,
	"csrf_token":      true,
	"xsrf-token":      true,
	"_csrf":           true,
	"laravel_session": true,
}

// Common session/token patterns that look like passwords but are actually session IDs
var sessionValuePatterns = []*regexp.Regexp{
	// Base64 encoded session data
	regexp.MustCompile(`^[A-Za-z0-9+/=]{20,}$`),
	// Hex encoded session IDs
	regexp.MustCompile(`^[a-f0-9]{32,}$`),
	// UUID patterns
	regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`),
	// URL-safe base64
	regexp.MustCompile(`^[A-Za-z0-9_-]{20,}$`),
}

func (d *cookiePasswordLeak) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()

			// Get cookies from response Set-Cookie headers
			cookies := flow.Response.Cookies()
			if len(cookies) == 0 {
				return nil
			}

			for _, cookie := range cookies {
				cookieNameLower := strings.ToLower(cookie.Name)

				// Skip well-known session cookie names
				if excludeCookieNames[cookieNameLower] {
					continue
				}

				// Skip empty cookie values
				if cookie.Value == "" {
					continue
				}

				// Check if the cookie name suggests it contains a password
				isPasswordCookieName := false
				for _, pattern := range passwordCookieNamePatterns {
					if strings.Contains(cookieNameLower, pattern) {
						isPasswordCookieName = true
						break
					}
				}

				if isPasswordCookieName {
					// Cookie name suggests password - report it
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "password-in-cookie: " + cookie.Name
						a.OutputVuln(v)
					}
					return nil
				}

				// Check if the cookie value looks like a password
				// Skip values that look like session IDs/tokens
				isSessionValue := false
				for _, pattern := range sessionValuePatterns {
					if pattern.MatchString(cookie.Value) {
						isSessionValue = true
						break
					}
				}
				if isSessionValue {
					continue
				}

				// Check if the value looks like a plaintext password
				for _, pattern := range passwordPatterns {
					if pattern.MatchString(cookie.Value) {
						// Additional heuristic: must contain both letters and digits
						hasLetter := false
						hasDigit := false
						for _, c := range cookie.Value {
							if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
								hasLetter = true
							}
							if c >= '0' && c <= '9' {
								hasDigit = true
							}
						}
						if hasLetter && hasDigit {
							v := a.NewWebVuln(flow.Request, flow.Response, nil)
							if v != nil {
								v.SetTargetURL(flow.Request.URL())
								v.Payload = "password-like-cookie-value: " + cookie.Name
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
			ID:       "baseline/sensitive/cookie-password-leak",
			Plugin:   "baseline/sensitive/cookie-password-leak",
			Category: "baseline/sensitive/cookie-password-leak",
			Severity: model.SeverityMedium,
		},
	}
}
