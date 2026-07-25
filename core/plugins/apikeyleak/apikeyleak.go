/**
* @Author: shaochuyu
* @Date: 6/16/2026
*
* API Key Leak Detection Plugin
* Strictly implemented following AWVS secret_key_leakage.js + text_search.js
*
* Key AWVS principles preserved:
*   1. Combined key-name + value regex with quote pairing (\1 \3 backreferences)
*   2. Separator includes comma: [=:\s,]
*   3. Exclusions mechanism (connection_strings_exclusions + per-pattern exclusions)
*   4. Only text/* content types scanned, body > 5MB skipped
*   5. No standalone value-only matching (AWVS only uses combined key+value)
*   6. Exact AWVS entropy thresholds per pattern
*   7. All AWVS secretKeys entries included with exact key names and value regexes
 */
package apikeyleak

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// Config holds the plugin configuration.
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	MinEntropy            float64 `json:"min_entropy" yaml:"min_entropy" #:"Shannon entropy minimum threshold for API key matches"`
	MaxBodySize           int     `json:"max_body_size" yaml:"max_body_size" #:"Maximum response body size to scan in bytes (default 5MB)"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// APIKeyLeak is the plugin struct for API key leak detection.
type APIKeyLeak struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
	patterns []keyPattern
}

// keyPattern defines a single API key detection rule.
// Strictly follows AWVS secretKeys structure.
type keyPattern struct {
	Name       string   // e.g. "Amazon AWS Secret Key"
	KeyRegex   string   // regex string for variable/key name (will be embedded into combined regex)
	ValueRegex string   // regex string for the key value (will be embedded into combined regex)
	MinEntropy float64  // minimum Shannon entropy for the matched value (AWVS per-pattern threshold)
	Exclusions []string // optional exclusion strings to check against matched value
}

// Close shuts down the plugin.
func (*APIKeyLeak) Close() error {
	return nil
}

// DefaultConfig returns the default plugin configuration.
func (*APIKeyLeak) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "apikey-leak",
			Enabled: true,
		},
		MinEntropy:  3.0,
		MaxBodySize: 5 * 1024 * 1024, // 5MB, same as AWVS text_search.js
	}
}

// Fingers returns the detection rules.
func (p *APIKeyLeak) Fingers() []*base.Finger {
	minEntropy := 3.0
	maxBodySize := 5 * 1024 * 1024
	if cfg, ok := p.GetConfig().(*Config); ok && cfg != nil {
		if cfg.MinEntropy > 0 {
			minEntropy = cfg.MinEntropy
		}
		if cfg.MaxBodySize > 0 {
			maxBodySize = cfg.MaxBodySize
		}
	}
	return []*base.Finger{
		(&apiKeyLeakCheck{patterns: p.patterns, minEntropy: minEntropy, maxBodySize: maxBodySize}).Finger(),
	}
}

// GetConfig returns the current plugin configuration.
func (p *APIKeyLeak) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin.
func (p *APIKeyLeak) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("APIKeyLeak init")
	p.PluginMixinInitConfig.Init(ctx, pci, ab)
	p.loadPatterns()
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// loadPatterns compiles all API key detection patterns.
func (p *APIKeyLeak) loadPatterns() {
	p.patterns = buildKeyPatterns()
}

// ============================================================================
// apiKeyLeakCheck - Finger implementation
// ============================================================================

type apiKeyLeakCheck struct {
	patterns    []keyPattern
	minEntropy  float64
	maxBodySize int
}

func (c *apiKeyLeakCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			// AWVS: only process text/* content types
			if !isTextResponse(flow.Response) {
				return nil
			}
			// AWVS: skip empty bodies
			if flow.Response.Text == "" {
				return nil
			}
			// AWVS: skip bodies > 5MB
			if len(flow.Response.Text) > c.maxBodySize {
				return nil
			}
			return nil
		},
		ExecAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow == nil || flow.Response == nil {
				return nil
			}
			// AWVS: only process text/* content types
			if !isTextResponse(flow.Response) {
				return nil
			}
			// AWVS: skip empty bodies
			if flow.Response.Text == "" {
				return nil
			}
			// AWVS: skip bodies > 5MB
			if len(flow.Response.Text) > c.maxBodySize {
				return nil
			}

			body := flow.Response.Text
			if body == "" {
				return nil
			}

			findings := lookForSecretKeyLeakage(body, c.patterns, c.minEntropy)
			for _, f := range findings {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = f.Name + ": " + f.MaskedValue
					v.Add("key_type", f.Name)
					v.Add("matched_value", f.MaskedValue)
					v.Add("entropy", fmt.Sprintf("%.2f", f.Entropy))
					v.Add("full_match", f.FullMatch)
					a.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "apikey-leak/secret-key-exposure",
			Plugin:   "apikey-leak/secret-key-exposure",
			Category: "apikey-leak/secret-key-exposure",
			Severity: model.SeverityHigh,
		},
	}
}

// ============================================================================
// Content type filtering (following AWVS text_search.js)
// ============================================================================

// isTextResponse checks if the response content is text-based and should be scanned.
// AWVS text_search.js: only processes content-type starting with "text/"
func isTextResponse(resp *http.Response) bool {
	contentType := strings.ToLower(resp.GetContentType())
	return strings.HasPrefix(contentType, "text/") ||
		strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "application/xml") ||
		strings.Contains(contentType, "application/javascript") ||
		strings.Contains(contentType, "application/x-javascript") ||
		strings.Contains(contentType, "text/")
}

// ============================================================================
// Shannon Entropy (same formula as AWVS secret_key_leakage.js)
// ============================================================================

// shannonEntropy calculates the Shannon entropy of a string in bits per symbol.
// H = -sum(pi * log2(pi))  — identical to AWVS entropy() function
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// ============================================================================
// Finding type
// ============================================================================

// finding represents a detected API key leak.
type finding struct {
	Name        string
	MaskedValue string
	FullMatch   string
	Entropy     float64
}

// maskValue partially masks a sensitive value for safe reporting.
// Shows first 4 and last 4 characters, replacing the middle with asterisks.
func maskValue(value string) string {
	runes := []rune(value)
	length := len(runes)
	if length <= 8 {
		return strings.Repeat("*", length)
	}
	prefix := string(runes[:4])
	suffix := string(runes[length-4:])
	return prefix + strings.Repeat("*", length-8) + suffix
}

// ============================================================================
// Scanning logic (strictly following AWVS lookForSecretKeyLeakage)
// ============================================================================

// lookForSecretKeyLeakage scans the body text for API key patterns.
// This is the Go equivalent of AWVS secret_key_leakage.js lookForSecretKeyLeakage().
//
// AWVS combined regex structure (JavaScript with backreferences):
//
//	([`'"\n]?)        group 1: optional opening quote or newline
//	{key.keys}        group 2: the key name
//	\1                backreference to group 1 (matching closing quote)
//	\s*               optional spaces
//	[=:\s,]           separator: = or : or space or comma
//	\s*               optional spaces
//	([`'"\n]?)        group 3: optional opening quote for value
//	{key.values}      group 4: the value
//	(\3)              group 5: backreference to group 3 (matching closing quote)
//	\s*               optional spaces
//	(\n|$|,|}|;|\))   group 6: terminator
//
// NOTE: Go's regexp (RE2) does NOT support backreferences (\1, \3).
// We emulate AWVS's behavior by:
//  1. Using separate capturing groups for open/close quotes
//  2. Post-validating quote pairing in Go code (same effect as backreferences)
//
// Our adapted regex:
//
//	([`'"\n]?)          group 1: optional opening quote/newline before key
//	(key_name)           group 2: the key name
//	([`'"\n]?)          group 3: optional closing quote after key
//	\s*
//	[=:\s,]             separator
//	\s*
//	([`'"\n]?)          group 4: optional opening quote/newline before value
//	(value)              group 5: the value
//	([`'"\n]?)          group 6: optional closing quote after value
//	\s*
//	(\n|$|,|}|;|\))     group 7: terminator
//
// Post-validation: group1 == group3 AND group4 == group6
func lookForSecretKeyLeakage(body string, patterns []keyPattern, globalMinEntropy float64) []finding {
	var findings []finding
	seen := make(map[string]bool) // deduplicate by masked value

	for _, pat := range patterns {
		// Build the combined regex adapted for Go RE2 (no backreferences):
		// We capture open/close quotes separately and validate pairing in code.
		//
		// IMPORTANT: pat.KeyRegex and pat.ValueRegex already contain their own
		// capturing groups from generateRegexFromKeyNames() and direct definition.
		// Do NOT wrap them in additional parentheses - that would create extra
		// capture groups and shift the group indices.
		//
		// Group layout:
		//   g1: open quote before key      ([`'"\n]?)
		//   g2: key name                   (from pat.KeyRegex, already parenthesized)
		//   g3: close quote after key       ([`'"\n]?)
		//   g4: open quote before value     ([`'"\n]?)
		//   g5: value                      (from pat.ValueRegex, already parenthesized)
		//   g6: close quote after value     ([`'"\n]?)
		//   g7: terminator                 (\n|$|,|}|;|\))
		combinedRegexStr := "([`'\"\\n]?)" + // group 1: optional opening quote/newline before key
			pat.KeyRegex + // group 2: key name (already parenthesized)
			"([`'\"\\n]?)" + // group 3: optional closing quote after key (must match group 1)
			"\\s*" +
			"[=:\\s,]" + // separator: =, :, space, or comma (AWVS: [=:\s,])
			"\\s*" +
			"([`'\"\\n]?)" + // group 4: optional opening quote/newline before value
			pat.ValueRegex + // group 5: value (already parenthesized)
			"([`'\"\\n]?)" + // group 6: optional closing quote after value (must match group 4)
			"\\s*" +
			"(\\n|$|,|}|;|\\))" // group 7: terminator

		keyRegex, err := regexp.Compile("(?im)" + combinedRegexStr)
		if err != nil {
			logger.Debug("Failed to compile regex for %s: %v", pat.Name, err)
			continue
		}

		// AWVS: do { match = keyRegex.exec(body) } while (match)
		matches := keyRegex.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			// groups: 1=open_quote_key, 2=key_name, 3=close_quote_key,
			//         4=open_quote_val, 5=value, 6=close_quote_val, 7=terminator
			if len(m) < 8 {
				continue
			}

			openQuoteKey := m[1]
			closeQuoteKey := m[3]
			openQuoteVal := m[4]
			closeQuoteVal := m[6]

			// Emulate AWVS backreferences: \1 and \3
			// Opening and closing quotes must match.
			// Special case: \n in the quote group means "no quote" (AWVS uses it
			// to match keys at the start of a line). Treat \n same as empty string.
			normalizeQuote := func(q string) string {
				if q == "\n" {
					return ""
				}
				return q
			}
			if normalizeQuote(openQuoteKey) != normalizeQuote(closeQuoteKey) {
				continue
			}
			if normalizeQuote(openQuoteVal) != normalizeQuote(closeQuoteVal) {
				continue
			}

			value := m[5]
			if value == "" {
				continue
			}

			// AWVS: check shannon entropy >= key.entropy
			ent := shannonEntropy(value)
			threshold := pat.MinEntropy
			if threshold < globalMinEntropy {
				threshold = globalMinEntropy
			}
			if ent < threshold {
				continue
			}

			// AWVS: check exclusions
			validHit := true
			if len(pat.Exclusions) > 0 {
				for _, exclusion := range pat.Exclusions {
					if strings.Contains(value, exclusion) {
						validHit = false
						break
					}
				}
			}

			if validHit {
				masked := maskValue(value)
				dedupeKey := pat.Name + ":" + masked
				if seen[dedupeKey] {
					continue
				}
				seen[dedupeKey] = true

				findings = append(findings, finding{
					Name:        pat.Name,
					MaskedValue: masked,
					FullMatch:   m[0],
					Entropy:     ent,
				})
			}
		}
	}

	return findings
}

// ============================================================================
// Key pattern definitions (strictly following AWVS secret_key_leakage.js)
// ============================================================================

// connection_strings_exclusions - same as AWVS
var connectionStringsExclusions = []string{"db_user", "db_password", "password", "username", "db_name", "test_user", "testing"}

// generateRegexFromKeyNames - exact equivalent of AWVS generateRegexFromKeyNames()
// Replaces underscores with [\_\-\.]? and joins with |
func generateRegexFromKeyNames(keyNames []string) string {
	var parts []string
	for _, name := range keyNames {
		parts = append(parts, strings.ReplaceAll(name, "_", "[\\_\\-\\.]?"))
	}
	return "(" + strings.Join(parts, "|") + ")"
}

// buildKeyPatterns creates all API key detection patterns.
// Each pattern exactly matches the corresponding entry in AWVS secretKeys array.
func buildKeyPatterns() []keyPattern {
	var patterns []keyPattern

	// AWVS: Amazon AWS Access Key ID (commented out in AWVS, but we include it
	// with the full prefix set from AWVS's commented version)
	// Note: inner alternation uses non-capturing group (?:...) to keep exactly 1 capture group
	patterns = append(patterns, keyPattern{
		Name:       "Amazon AWS Access Key ID",
		KeyRegex:   generateRegexFromKeyNames([]string{"aws_access_key_id", "access_key_id", "secret_access_key", "secret_access_key_id", "access_key"}),
		ValueRegex: "((?:A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})",
		MinEntropy: 3.0,
	})

	// AWVS: Amazon AWS Secret Key
	patterns = append(patterns, keyPattern{
		Name:       "Amazon AWS Secret Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"aws_secret_access_key", "amazon_secret_access_key", "access_key_secret", "aws_secret_key", "secret_access_key", "aws_ses_secret_access_key"}),
		ValueRegex: "([0-9a-zA-Z/+]{40})",
		MinEntropy: 3.0,
	})

	// AWVS: Facebook App Secret
	patterns = append(patterns, keyPattern{
		Name:       "Facebook App Secret",
		KeyRegex:   generateRegexFromKeyNames([]string{"facebook_secret", "app_secret", "client_secret", "fb_app_secret", "facebook_app_secret"}),
		ValueRegex: "([0-9a-f]{32})",
		MinEntropy: 3.0,
	})

	// AWVS: Facebook App Token
	patterns = append(patterns, keyPattern{
		Name:       "Facebook App Token",
		KeyRegex:   generateRegexFromKeyNames([]string{"access_token", "fb_access_token", "facebook_access_token", "app_token", "fb_app_token", "facebook_app_token"}),
		ValueRegex: "(\\d{15}\\|\\w{27})",
		MinEntropy: 4.0,
	})

	// AWVS: Twitter API Secret Key
	patterns = append(patterns, keyPattern{
		Name:       "Twitter API Secret Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"secret_key", "twitter_secret_key", "twitter_secret", "twitter_api_secret_key"}),
		ValueRegex: "([0-9a-zA-Z]{43}|[0-9a-zA-Z]{50})",
		MinEntropy: 4.0,
	})

	// AWVS: Twitter Access Token Secret
	patterns = append(patterns, keyPattern{
		Name:       "Twitter Access Token Secret",
		KeyRegex:   generateRegexFromKeyNames([]string{"access_token", "access_token_secret", "token_secret", "twitter_access_token_secret"}),
		ValueRegex: "([0-9a-zA-Z]{45})",
		MinEntropy: 4.0,
	})

	// AWVS: Heroku API Key
	patterns = append(patterns, keyPattern{
		Name:       "Heroku API Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"heroku_api_key"}),
		ValueRegex: "([0-9a-z]{8}\\-[0-9a-z]{4}\\-[0-9a-z]{4}\\-[0-9a-z]{4}\\-[0-9a-z]{12})",
		MinEntropy: 3.0,
	})

	// AWVS: SSH Key
	patterns = append(patterns, keyPattern{
		Name:       "SSH Key",
		KeyRegex:   "(rsa\\-key|ssh\\-rsa)",
		ValueRegex: "([0-9a-zA-Z\\+=/]{200})\\s[a-zA-Z0-9\\-]{16,}",
		MinEntropy: 5.0, // AWVS: 5
	})

	// AWVS: SendGrid API Key
	patterns = append(patterns, keyPattern{
		Name:       "SendGrid API Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"sendgrid", "sendgrid_key", "sendgrid_api", "sendgrid_api_key"}),
		ValueRegex: "(SG\\.[a-zA-z0-9-]{22}\\.[a-zA-z0-9-]{43})",
		MinEntropy: 4.0,
	})

	// AWVS: Google Cloud API Key
	patterns = append(patterns, keyPattern{
		Name:       "Google Cloud API Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"firebase", "firebase_token", "google_cloud_api_key", "cloud_api_key", "cloud_api", "google_cloud_api"}),
		ValueRegex: "(AIza[0-9A-Za-z\\-_]{35})",
		MinEntropy: 4.0,
	})

	// AWVS: reCAPTCHA Secret Key
	patterns = append(patterns, keyPattern{
		Name:       "Google reCAPTCHA Secret Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"recaptcha_secret_key", "captcha_secret_key"}),
		ValueRegex: "(6Ld[0-9A-Za-z\\-_]{37})",
		MinEntropy: 4.0,
	})

	// AWVS: MailGun API Key
	patterns = append(patterns, keyPattern{
		Name:       "MailGun API Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"mailgun", "mailgun_api_key"}),
		ValueRegex: "(key-[0-9a-zA-Z]{32})",
		MinEntropy: 4.0,
	})

	// AWVS: NuGet API Key
	patterns = append(patterns, keyPattern{
		Name:       "NuGet API Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"nuget_api_key"}),
		ValueRegex: "(oy2[a-z0-9]{43})",
		MinEntropy: 3.0,
	})

	// AWVS: Slack Webhook
	patterns = append(patterns, keyPattern{
		Name:       "Slack Webhook",
		KeyRegex:   generateRegexFromKeyNames([]string{"uri", "url", "slack", "slack_webhook", "webhook", "webhook_uri", "webhook_url"}),
		ValueRegex: "(https://hooks\\.slack\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24})",
		MinEntropy: 4.0,
		Exclusions: []string{"ABC123DEF456GHI789000XXX", "T12345678", "B98765432"}, // AWVS exclusions
	})

	// AWVS: Slack Token
	// Note: alternation wrapped in non-capturing group to keep exactly 1 capture group
	patterns = append(patterns, keyPattern{
		Name:       "Slack Token",
		KeyRegex:   generateRegexFromKeyNames([]string{"slack", "slack_token", "token"}),
		ValueRegex: "(xox[pboa]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}|xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
		MinEntropy: 4.0,
	})

	// AWVS: Slack v1.x Token
	patterns = append(patterns, keyPattern{
		Name:       "Slack v1.x Token",
		KeyRegex:   generateRegexFromKeyNames([]string{"slack", "slack_token", "token"}),
		ValueRegex: "(xox[p|b|o|a]-[0-9]{1,}-[0-9]{1,}-[a-zA-Z0-9]{24})",
		MinEntropy: 4.0,
	})

	// AWVS: Stripe API key
	// Note: (?:r|s) is non-capturing to keep exactly 1 capture group
	patterns = append(patterns, keyPattern{
		Name:       "Stripe API Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"stripe", "stripe_api_key", "api_key"}),
		ValueRegex: "((?:r|s)k_live_[0-9a-zA-Z]{24})",
		MinEntropy: 4.0,
	})

	// AWVS: MailChimp API Key
	patterns = append(patterns, keyPattern{
		Name:       "MailChimp API Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"mailchimp_api_key", "mailchimp"}),
		ValueRegex: "([0-9a-f]{32}-\\w\\w[0-9])",
		MinEntropy: 3.0,
	})

	// AWVS: LinkedIn API Key
	patterns = append(patterns, keyPattern{
		Name:       "LinkedIn API Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"linkedin_secret", "linkedin"}),
		ValueRegex: "([0-9a-zA-Z]{16})",
		MinEntropy: 3.0,
	})

	// AWVS: Google API Key (non-Cloud)
	patterns = append(patterns, keyPattern{
		Name:       "Google API Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"google_secret", "google_api_key"}),
		ValueRegex: "([a-zA-z0-9-]{24})",
		MinEntropy: 4.0,
	})

	// AWVS: Database Connection String
	patterns = append(patterns, keyPattern{
		Name:       "Database Connection String",
		KeyRegex:   generateRegexFromKeyNames([]string{"uri", "postgresql", "postgres", "mongodb", "mongo", "mysql", "mysqldb", "url", "db_url", "db_uri"}),
		ValueRegex: "((?:mongodb|mysql|postgresql)://[a-zA-z0-9-]{4,}:[a-zA-z0-9-]{6,}@[a-zA-Z0-9-\\.]+:\\d+/.*?)",
		MinEntropy: 4.0,
		Exclusions: connectionStringsExclusions, // AWVS: connection_strings_exclusions
	})

	// AWVS: JDBC Database Connection String
	patterns = append(patterns, keyPattern{
		Name:       "JDBC Database Connection String",
		KeyRegex:   generateRegexFromKeyNames([]string{"uri", "jdbc", "postgresql", "postgres", "mongodb", "mongo", "mysql", "mysqldb", "url", "db_url", "db_uri"}),
		ValueRegex: "(jdbc:(?:mongodb|mysql|postgresql)://[a-zA-Z0-9-\\.]+:\\d+/.*\\?user=[a-zA-z0-9-]{5,}\\&password=[a-zA-z0-9-]{5,}.*?)",
		MinEntropy: 4.0,
		Exclusions: connectionStringsExclusions, // AWVS: connection_strings_exclusions
	})

	// AWVS: WordPress Authentication Key/Salt
	// KeyRegex uses alternation - must be non-capturing to keep exactly 1 capture group
	// But generateRegexFromKeyNames already wraps in a single group.
	// For direct KeyRegex, we use (?:...) for inner alternation.
	patterns = append(patterns, keyPattern{
		Name:       "WordPress Auth Key/Salt",
		KeyRegex:   "(AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)",
		ValueRegex: "([ -~]{64})",
		MinEntropy: 5.0,
	})

	// AWVS: Symfony Application Secret
	patterns = append(patterns, keyPattern{
		Name:       "Symfony Application Secret",
		KeyRegex:   generateRegexFromKeyNames([]string{"app_secret"}),
		ValueRegex: "([a-zA-Z0-9]{32})",
		MinEntropy: 3.0,
	})

	// AWVS: Mapbox Token
	patterns = append(patterns, keyPattern{
		Name:       "Mapbox Token",
		KeyRegex:   generateRegexFromKeyNames([]string{"mapbox_token"}),
		ValueRegex: "(pk\\.eyJ1IjoiY[0-9A-Za-z\\-_\\.]{78,82})",
		MinEntropy: 4.0,
	})

	// AWVS: Amazon SES SMTP Password
	patterns = append(patterns, keyPattern{
		Name:       "Amazon SES SMTP Password",
		KeyRegex:   generateRegexFromKeyNames([]string{"amazon_ses_smtp_password", "smtp_password"}),
		ValueRegex: "([0-9A-Za-z]{44})",
		MinEntropy: 4.5,
	})

	// AWVS: Sentry Auth Token
	patterns = append(patterns, keyPattern{
		Name:       "Sentry Auth Token",
		KeyRegex:   generateRegexFromKeyNames([]string{"auth_token", "sentry_auth_token"}),
		ValueRegex: "([0-9A-Za-z]{64})",
		MinEntropy: 3.0,
	})

	// AWVS: Outlook Team Webhook
	patterns = append(patterns, keyPattern{
		Name:       "Outlook Team Webhook",
		KeyRegex:   generateRegexFromKeyNames([]string{"uri", "url", "outlook", "outlook_webhook", "webhook", "webhook_uri", "webhook_url"}),
		ValueRegex: "(https\\://outlook\\.office\\.com/webhook/[0-9a-f-]{36}\\@.*)",
		MinEntropy: 4.0,
	})

	// AWVS: Twilio API Key
	patterns = append(patterns, keyPattern{
		Name:       "Twilio API Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"twilio", "twilio_token", "twilio_api_token"}),
		ValueRegex: "([0-9a-f]{32})",
		MinEntropy: 3.0,
	})

	// AWVS: Paypal Access Token
	patterns = append(patterns, keyPattern{
		Name:       "PayPal Access Token",
		KeyRegex:   generateRegexFromKeyNames([]string{"braintree", "paypal", "access_token", "paypal_access_token", "braintree_access_token"}),
		ValueRegex: "(access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32})",
		MinEntropy: 4.0,
	})

	// AWVS: Square Access Token
	patterns = append(patterns, keyPattern{
		Name:       "Square Access Token",
		KeyRegex:   generateRegexFromKeyNames([]string{"square", "access_token", "square_access_token"}),
		ValueRegex: "(sq0atp-[0-9A-Za-z\\-_]{22})",
		MinEntropy: 3.0,
	})

	// AWVS: Square OAuth Secret
	patterns = append(patterns, keyPattern{
		Name:       "Square OAuth Secret",
		KeyRegex:   generateRegexFromKeyNames([]string{"square", "oauth_secret", "square_oauth_secret"}),
		ValueRegex: "(sq0csp-[0-9A-Za-z\\-_]{43})",
		MinEntropy: 3.0,
	})

	// AWVS: Picatic API key
	patterns = append(patterns, keyPattern{
		Name:       "Picatic API Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"picatic", "aicatic_api_key", "api_key"}),
		ValueRegex: "(sk_live_[0-9a-z]{32})",
		MinEntropy: 3.0,
	})

	// AWVS: Amazon MWS Auth Token
	patterns = append(patterns, keyPattern{
		Name:       "Amazon MWS Auth Token",
		KeyRegex:   generateRegexFromKeyNames([]string{"amazon_mws_auth_token", "amzn_mws_auth_token", "mws_auth_token", "auth_token"}),
		ValueRegex: "(amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
		MinEntropy: 3.0,
	})

	// AWVS: Google OAuth Access Token
	patterns = append(patterns, keyPattern{
		Name:       "Google OAuth Access Token",
		KeyRegex:   generateRegexFromKeyNames([]string{"google_oauth_access_token", "oauth_access_token", "access_token", "oauth_token"}),
		ValueRegex: "(ya29\\.[0-9A-Za-z\\-_]+)",
		MinEntropy: 5.0,
	})

	// AWVS: Facebook Access Token
	patterns = append(patterns, keyPattern{
		Name:       "Facebook Access Token",
		KeyRegex:   generateRegexFromKeyNames([]string{"facebook", "facebook_access_token", "access_token"}),
		ValueRegex: "(EAACEdEose0cBA[0-9A-Za-z]{150,})",
		MinEntropy: 5.3, // AWVS: 5.3
	})

	// AWVS: SonarQube API Key
	patterns = append(patterns, keyPattern{
		Name:       "SonarQube API Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"sonar", "sonarqube", "sonar_key", "sonar_api", "sonar_api_key", "sonar_login"}),
		ValueRegex: "([0-9a-f]{40})",
		MinEntropy: 3.0,
	})

	// AWVS: Nexmo Secret
	patterns = append(patterns, keyPattern{
		Name:       "Nexmo Secret",
		KeyRegex:   generateRegexFromKeyNames([]string{"nexmo", "nexmo_secret"}),
		ValueRegex: "([0-9a-f]{16})",
		MinEntropy: 3.0,
	})

	// AWVS: Telegram Token
	patterns = append(patterns, keyPattern{
		Name:       "Telegram Bot Token",
		KeyRegex:   generateRegexFromKeyNames([]string{"telegram_token", "telegram"}),
		ValueRegex: "([0-9]{9}:[a-zA-Z0-9_-]{35})",
		MinEntropy: 4.0,
	})

	// AWVS: Devise Secret Key
	patterns = append(patterns, keyPattern{
		Name:       "Devise Secret Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"secret_key", "devise_key", "devise_secret_key"}),
		ValueRegex: "([0-9a-f]{128})",
		MinEntropy: 3.5, // AWVS: 3.5
	})

	// AWVS: Gitlab API Private Token
	patterns = append(patterns, keyPattern{
		Name:       "GitLab API Private Token",
		KeyRegex:   generateRegexFromKeyNames([]string{"gitlab_api_private_token", "api_private_token", "private_token"}),
		ValueRegex: "([a-zA-Z0-9_-]{20})", // AWVS: exact 20 chars
		MinEntropy: 3.5,                   // AWVS: 3.5
	})

	// AWVS: Consul Token
	patterns = append(patterns, keyPattern{
		Name:       "Consul Token",
		KeyRegex:   generateRegexFromKeyNames([]string{"consul_token", "consul"}),
		ValueRegex: "([0-9a-zA-Z\\+=/]{24})",
		MinEntropy: 4.0,
	})

	// AWVS: Omise Secret Key
	patterns = append(patterns, keyPattern{
		Name:       "Omise Secret Key",
		KeyRegex:   generateRegexFromKeyNames([]string{"omise_skey", "secret_key", "omise_secret_key", "omise"}),
		ValueRegex: "(skey_[0-9a-zA-Z]{19})",
		MinEntropy: 3.0,
	})

	return patterns
}
