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

type autoCompleteLeak struct{}

// Regex to find <input> elements
var inputTagRegex = regexp.MustCompile(`(?i)<input[^>]+>`)

// Regex to check for autocomplete attribute
var autoCompleteAttrRegex = regexp.MustCompile(`(?i)\bautocomplete\s*=\s*["']?\s*off`)

// Sensitive input type attributes that should have autocomplete=off
var sensitiveInputTypes = map[string]bool{
	"password": true,
	"hidden":   false, // hidden inputs are not user-facing, skip
}

// Sensitive input name/id patterns that suggest password or credential fields
var sensitiveFieldPatterns = []string{
	"password", "passwd", "pwd", "pass",
	"secret", "token", "credential",
	"creditcard", "credit_card", "cc_number", "ccnumber",
	"cvv", "cvc", "ccv",
	"ssn", "social_security",
	"pin", "pincode",
	"taxid", "tax_id",
	"auth", "private",
}

func (d *autoCompleteLeak) Finger() *base.Finger {
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

			// Find all input elements
			inputs := inputTagRegex.FindAllString(body, -1)
			if len(inputs) == 0 {
				return nil
			}

			for _, input := range inputs {
				if !isSensitiveInput(input) {
					continue
				}

				// Check if autocomplete=off is set
				if autoCompleteAttrRegex.MatchString(input) {
					continue // Has autocomplete=off, which is correct
				}

				// Sensitive field without autocomplete=off
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "missing-autocomplete-off: " + truncateString(input, 200)
					a.OutputVuln(v)
				}
				return nil
			}

			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/config/autocomplete-missing",
			Plugin:   "baseline/config/autocomplete-missing",
			Category: "baseline/config/autocomplete-missing",
			Severity: model.SeverityLow,
		},
	}
}

// isSensitiveInput determines if an input element is for a sensitive field
func isSensitiveInput(inputTag string) bool {
	inputLower := strings.ToLower(inputTag)

	// Check for type="password" — always sensitive
	if strings.Contains(inputLower, `type="password"`) || strings.Contains(inputLower, "type='password'") {
		return true
	}

	// Check the name and id attributes against sensitive patterns
	for _, pattern := range sensitiveFieldPatterns {
		// Check name attribute
		if strings.Contains(inputLower, `name="`+pattern+`"`) ||
			strings.Contains(inputLower, `name='`+pattern+`'`) ||
			strings.Contains(inputLower, `name=`+pattern) {
			return true
		}
		// Check id attribute
		if strings.Contains(inputLower, `id="`+pattern+`"`) ||
			strings.Contains(inputLower, `id='`+pattern+`'`) ||
			strings.Contains(inputLower, `id=`+pattern) {
			return true
		}
		// Partial match for name containing the pattern
		nameRegex := regexp.MustCompile(`(?i)\bname\s*=\s*["']?[^"'>]*` + pattern + `[^"'>]*["']?`)
		if nameRegex.MatchString(inputLower) {
			return true
		}
		idRegex := regexp.MustCompile(`(?i)\bid\s*=\s*["']?[^"'>]*` + pattern + `[^"'>]*["']?`)
		if idRegex.MatchString(inputLower) {
			return true
		}
	}

	return false
}
