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

type serializationDataInParams struct{}

// Pre-compiled regex patterns for detecting serialized data
var (
	// Java serialization: rO0AB (base64 of 0xACED0005, Java serialization magic number)
	javaSerializedRegex = regexp.MustCompile(`rO0AB[A-Za-z0-9+/=]{4,}`)
	// PHP serialization: a:N:{...} or O:N:"ClassName":...
	phpSerializedRegex = regexp.MustCompile(`(?:[aOsSiN]:\d+:[{"]|[aO]:\d+:\{)`)
	// .NET ViewState: /wE (base64 of viewstate marker)
	dotnetViewStateRegex = regexp.MustCompile(`(?:^|[^A-Za-z0-9+/])/wE[A-Za-z0-9+/=]{8,}`)
	// Python pickle: gASV (common pickle protocol marker in base64)
	pythonPickleRegex = regexp.MustCompile(`gASV[A-Za-z0-9+/=]{4,}`)
	// Ruby Marshal: BAhv (base64 of 0x04\x08, Ruby marshal data)
	rubyMarshalRegex = regexp.MustCompile(`BAhv[A-Za-z0-9+/=]{4,}`)
)

func (d *serializationDataInParams) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			// Skip non-text responses
			if flow.Response.IsJavaScript() || flow.Response.IsCss() || flow.Response.IsImage() {
				return nil
			}

			// Check all request parameters (query, body, cookie, header)
			for _, param := range flow.Request.ParamsAll() {
				if param.Value == "" {
					continue
				}
				value := param.Value
				found := false
				matchType := ""

				if javaSerializedRegex.MatchString(value) {
					found = true
					matchType = "Java serialization"
				} else if phpSerializedRegex.MatchString(value) {
					found = true
					matchType = "PHP serialization"
				} else if dotnetViewStateRegex.MatchString(value) {
					found = true
					matchType = ".NET ViewState"
				} else if pythonPickleRegex.MatchString(value) {
					found = true
					matchType = "Python pickle"
				} else if rubyMarshalRegex.MatchString(value) {
					found = true
					matchType = "Ruby Marshal"
				}

				if found {
					payloadDisplay := matchType + " data in param '" + param.Key + "'"
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = payloadDisplay
						a.OutputVuln(v)
					}
					return nil
				}
			}

			// Also check response body for serialized data patterns
			body := flow.Response.Text
			if body == "" {
				return nil
			}

			serializedPatterns := []struct {
				regex *regexp.Regexp
				name  string
			}{
				{javaSerializedRegex, "Java serialization"},
				{phpSerializedRegex, "PHP serialization"},
				{dotnetViewStateRegex, ".NET ViewState"},
				{pythonPickleRegex, "Python pickle"},
				{rubyMarshalRegex, "Ruby Marshal"},
			}

			for _, pattern := range serializedPatterns {
				matches := pattern.regex.FindAllString(body, -1)
				if len(matches) > 0 {
					for _, m := range matches {
						// Skip very short matches that are likely false positives
						if len(m) < 10 {
							continue
						}
						v := a.NewWebVuln(flow.Request, flow.Response, nil)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = pattern.name + " data detected: " + truncateString(m, 100)
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
			ID:       "baseline/sensitive/serialization-data",
			Plugin:   "baseline/sensitive/serialization-data",
			Category: "baseline/sensitive/serialization-data",
			Severity: model.SeverityLow,
		},
	}
}

// truncateString truncates a string to maxLen characters with ellipsis
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
