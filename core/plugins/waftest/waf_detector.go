/**
* @Author: wscan
* @Date: 2026/06/16
* WAF Detection Engine - Implements 3 detection methods:
* 1. Passive Detection: Scan HTTP response headers, cookies, body for WAF fingerprints
* 2. Active Probing: Send malicious requests and analyze responses
* 3. Behavior Analysis: Compare attack response vs baseline response
 */
package waftest

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	wscanhttp "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// WAFDetectionResult represents the result of WAF detection
type WAFDetectionResult struct {
	Detected   bool     // Whether a WAF was detected
	Name       string   // WAF product name
	Vendor     string   // WAF vendor
	Category   string   // WAF category
	Confidence int      // Confidence score 0-100
	Method     string   // Detection method: "passive", "active", "behavior"
	BypassTips []string // Suggested bypass methods
	Evidence   string   // Evidence string describing why WAF was detected
}

// WAFDetector performs WAF detection using multiple methods
type WAFDetector struct {
	fingerprints []WAFFingerprint
	cfg          *Config
}

// NewWAFDetector creates a new WAF detector with built-in fingerprints
func NewWAFDetector(cfg *Config) *WAFDetector {
	return &WAFDetector{
		fingerprints: BuiltInWAFFingerprints(),
		cfg:          cfg,
	}
}

// DetectPassive performs passive WAF detection by analyzing HTTP response
// It scans headers, cookies, body, and status codes for WAF fingerprints
func (d *WAFDetector) DetectPassive(res *wscanhttp.Response) *WAFDetectionResult {
	if res == nil {
		return nil
	}

	var bestResult *WAFDetectionResult

	for _, fp := range d.fingerprints {
		score := 0
		evidence := []string{}

		// Check header patterns
		if len(fp.Headers) > 0 {
			for headerPattern, valuePattern := range fp.Headers {
				if matched, ev := d.matchHeaders(res, headerPattern, valuePattern); matched {
					score += 25
					evidence = append(evidence, ev)
				}
			}
		}

		// Check cookie patterns
		if len(fp.Cookies) > 0 {
			if matched, ev := d.matchCookies(res, fp.Cookies); matched {
				score += 30
				evidence = append(evidence, ev)
			}
		}

		// Check body patterns
		if len(fp.BodyPatterns) > 0 {
			if matched, ev := d.matchBodyPatterns(res, fp.BodyPatterns); matched {
				score += 20
				evidence = append(evidence, ev)
			}
		}

		// Check characteristic status codes
		if len(fp.StatusCodes) > 0 {
			for _, code := range fp.StatusCodes {
				if res.StatusCode == code {
					score += 10
					evidence = append(evidence, fmt.Sprintf("Status code: %d", code))
					break
				}
			}
		}

		// If we have enough evidence, consider this WAF detected
		if score >= 20 && (bestResult == nil || score > bestResult.Confidence) {
			confidence := score
			if confidence > 100 {
				confidence = 100
			}
			bestResult = &WAFDetectionResult{
				Detected:   true,
				Name:       fp.Name,
				Vendor:     fp.Vendor,
				Category:   fp.Category,
				Confidence: confidence,
				Method:     "passive",
				BypassTips: fp.BypassTips,
				Evidence:   strings.Join(evidence, "; "),
			}
		}
	}

	return bestResult
}

// DetectActive performs active WAF probing by sending malicious requests
// and analyzing the responses for WAF blocking patterns
func (d *WAFDetector) DetectActive(ctx context.Context, ab *base.Apollo, targetURL string) *WAFDetectionResult {
	if ab == nil || ab.HTTPClient == nil {
		return nil
	}

	// Step 1: Get baseline response
	baselineRes, baselineErr := d.sendBaselineRequest(ctx, ab, targetURL)
	if baselineErr != nil {
		logger.Debugf("WAF detection: baseline request failed: %v", baselineErr)
		return nil
	}

	// Step 2: Send attack probes
	attackResults := d.sendAttackProbes(ctx, ab, targetURL)
	if len(attackResults) == 0 {
		return nil
	}

	// Step 3: Analyze attack responses against WAF fingerprints
	bestResult := d.analyzeAttackResponses(attackResults, baselineRes)

	// Step 4: If no specific WAF fingerprint matched, try behavior analysis
	if bestResult == nil || bestResult.Confidence < 40 {
		behaviorResult := d.DetectBehavior(attackResults, baselineRes)
		if behaviorResult != nil {
			if bestResult == nil || behaviorResult.Confidence > bestResult.Confidence {
				bestResult = behaviorResult
			}
		}
	}

	return bestResult
}

// DetectBehavior performs behavior-based WAF detection by comparing
// attack responses against a baseline normal response
func (d *WAFDetector) DetectBehavior(attackResults []*probeResult, baselineRes *wscanhttp.Response) *WAFDetectionResult {
	if baselineRes == nil || len(attackResults) == 0 {
		return nil
	}

	baselineStatusCode := baselineRes.StatusCode
	baselineBodyHash := bodyHash(baselineRes.Text)
	baselineContentLen := len(baselineRes.Text)

	blockedCount := 0
	sameAsBaseline := 0
	blockStatusCodes := d.getBlockStatusCodes()

	for _, ar := range attackResults {
		if ar.response == nil {
			continue
		}

		// Check if attack response differs significantly from baseline
		attackStatusCode := ar.response.StatusCode
		attackBodyHash := bodyHash(ar.response.Text)
		attackContentLen := len(ar.response.Text)

		isBlocked := false

		// Status code indicates blocking
		for _, blockCode := range blockStatusCodes {
			if attackStatusCode == blockCode {
				isBlocked = true
				break
			}
		}

		// Status code changed from baseline to a 4xx/5xx
		if !isBlocked && attackStatusCode != baselineStatusCode {
			if attackStatusCode >= 400 && baselineStatusCode < 400 {
				isBlocked = true
			}
		}

		// Body changed significantly (different hash and substantial content length difference)
		if !isBlocked && attackBodyHash != baselineBodyHash {
			contentLenDiff := abs(attackContentLen - baselineContentLen)
			if contentLenDiff > 100 && attackStatusCode >= 400 {
				isBlocked = true
			}
		}

		if isBlocked {
			blockedCount++
		} else if attackStatusCode == baselineStatusCode && attackBodyHash == baselineBodyHash {
			sameAsBaseline++
		}
	}

	// If most attack probes were blocked and baseline was different, WAF is likely present
	totalProbes := len(attackResults)
	if totalProbes > 0 && blockedCount >= totalProbes/2 && sameAsBaseline < totalProbes/3 {
		confidence := (blockedCount * 100) / totalProbes
		if confidence > 90 {
			confidence = 90
		}
		return &WAFDetectionResult{
			Detected:   true,
			Name:       "Unknown WAF",
			Vendor:     "Unknown",
			Category:   "unknown",
			Confidence: confidence,
			Method:     "behavior",
			BypassTips: []string{
				"Try HTTP parameter pollution (duplicate parameters)",
				"Try chunked transfer encoding",
				"Try double URL encoding",
				"Try Unicode/HTML entity encoding",
				"Try inline comments for SQL injection: /*!SELECT*/",
				"Try multipart/form-data instead of application/x-www-form-urlencoded",
				"Try HTTP/1.0 protocol version",
				"Try path parameter pollution (;/path)",
			},
			Evidence: fmt.Sprintf("Behavior analysis: %d/%d attack probes blocked, %d same as baseline",
				blockedCount, totalProbes, sameAsBaseline),
		}
	}

	return nil
}

// probeResult holds the result of an attack probe
type probeResult struct {
	probeName string
	request   *wscanhttp.Request
	response  *wscanhttp.Response
	err       error
}

// attackProbe defines an active WAF detection probe
type attackProbe struct {
	name    string
	method  string
	path    string
	query   string
	headers map[string]string
}

// getAttackProbes returns the list of attack probes for active WAF detection
func getAttackProbes() []attackProbe {
	return []attackProbe{
		{
			name:   "invalid_filename",
			method: "GET",
			path:   "/../../../etc/passwd",
		},
		{
			name:   "malformed_method",
			method: "JEKYLL",
			path:   "/",
		},
		{
			name:   "xss_probe",
			method: "GET",
			path:   "/",
			query:  "?id=<script>alert(1)</script>",
		},
		{
			name:   "sqli_probe",
			method: "GET",
			path:   "/",
			query:  "?id=1'+OR+'1'='1",
		},
		{
			name:   "path_traversal",
			method: "GET",
			path:   "/",
			query:  "?file=../../etc/passwd",
		},
		{
			name:   "cmd_injection",
			method: "GET",
			path:   "/",
			query:  "?cmd=;cat+/etc/passwd",
		},
		{
			name:   "oversized_param",
			method: "GET",
			path:   "/",
			query:  fmt.Sprintf("?param=%s", strings.Repeat("A", 2048)),
		},
		{
			name:   "invalid_protocol",
			method: "GET",
			path:   "/",
			headers: map[string]string{
				// Force HTTP/1.0 to trigger protocol-level detection
				"Connection": "close",
			},
		},
	}
}

// sendBaselineRequest sends a normal/innocent request to establish a baseline
func (d *WAFDetector) sendBaselineRequest(ctx context.Context, ab *base.Apollo, targetURL string) (*wscanhttp.Response, error) {
	req, err := wscanhttp.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create baseline request: %w", err)
	}
	return ab.HTTPClient.Respond(ctx, req)
}

// sendAttackProbes sends all attack probes and collects responses
func (d *WAFDetector) sendAttackProbes(ctx context.Context, ab *base.Apollo, targetURL string) []*probeResult {
	probes := getAttackProbes()
	results := make([]*probeResult, 0, len(probes))

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		logger.Debugf("WAF detection: failed to parse target URL: %v", err)
		return nil
	}

	for _, probe := range probes {
		// Construct the probe URL
		probeURL := *parsedURL
		probePath := probe.path
		if probePath == "" {
			probePath = "/"
		}
		probeURL.Path = probePath
		probeURL.RawQuery = ""

		fullURL := probeURL.String()
		if probe.query != "" {
			fullURL = fullURL + probe.query
		}

		req, err := wscanhttp.NewRequest(probe.method, fullURL, nil)
		if err != nil {
			logger.Debugf("WAF detection: create probe request '%s' failed: %v", probe.name, err)
			results = append(results, &probeResult{
				probeName: probe.name,
				err:       err,
			})
			continue
		}

		// Add any extra headers
		for k, v := range probe.headers {
			req.SetHeader(k, v)
		}

		res, err := ab.HTTPClient.Respond(ctx, req)
		results = append(results, &probeResult{
			probeName: probe.name,
			request:   req,
			response:  res,
			err:       err,
		})

		if err != nil {
			logger.Debugf("WAF detection: probe '%s' request error: %v", probe.name, err)
		}
	}

	return results
}

// analyzeAttackResponses checks attack probe responses against WAF fingerprints
func (d *WAFDetector) analyzeAttackResponses(attackResults []*probeResult, baselineRes *wscanhttp.Response) *WAFDetectionResult {
	var bestResult *WAFDetectionResult

	for _, fp := range d.fingerprints {
		if fp.BlockResponse == nil {
			continue
		}

		matchCount := 0
		evidence := []string{}

		for _, ar := range attackResults {
			if ar.response == nil || ar.err != nil {
				continue
			}

			matched := false

			// Check block status codes
			if len(fp.BlockResponse.StatusCodes) > 0 {
				for _, code := range fp.BlockResponse.StatusCodes {
					if ar.response.StatusCode == code {
						matched = true
						evidence = append(evidence, fmt.Sprintf("%s: status %d", ar.probeName, ar.response.StatusCode))
						break
					}
				}
			}

			// Check block body patterns
			if !matched && len(fp.BlockResponse.BodyPatterns) > 0 {
				for _, pattern := range fp.BlockResponse.BodyPatterns {
					if re, err := regexp.Compile(pattern); err == nil {
						if re.MatchString(ar.response.Text) {
							matched = true
							evidence = append(evidence, fmt.Sprintf("%s: body matches %q", ar.probeName, pattern))
							break
						}
					} else if strings.Contains(ar.response.Text, pattern) {
						// Fall back to literal match if regex compilation fails
						matched = true
						evidence = append(evidence, fmt.Sprintf("%s: body contains %q", ar.probeName, pattern))
						break
					}
				}
			}

			// Check block header patterns
			if !matched && len(fp.BlockResponse.HeaderPatterns) > 0 {
				for headerName, valuePattern := range fp.BlockResponse.HeaderPatterns {
					headerVal := ar.response.Header.Get(headerName)
					if headerVal != "" {
						if valuePattern == "" {
							matched = true
							evidence = append(evidence, fmt.Sprintf("%s: header %s present", ar.probeName, headerName))
						} else if re, err := regexp.Compile(valuePattern); err == nil && re.MatchString(headerVal) {
							matched = true
							evidence = append(evidence, fmt.Sprintf("%s: header %s matches %q", ar.probeName, headerName, valuePattern))
						}
					}
				}
			}

			if matched {
				matchCount++
			}
		}

		// If multiple attack probes match this WAF's blocking pattern
		if matchCount >= 2 && (bestResult == nil || matchCount > bestResult.Confidence/10) {
			confidence := matchCount * 15
			if confidence > 95 {
				confidence = 95
			}
			bestResult = &WAFDetectionResult{
				Detected:   true,
				Name:       fp.Name,
				Vendor:     fp.Vendor,
				Category:   fp.Category,
				Confidence: confidence,
				Method:     "active",
				BypassTips: fp.BypassTips,
				Evidence:   strings.Join(evidence, "; "),
			}
		}
	}

	return bestResult
}

// matchHeaders checks if response headers match fingerprint header patterns
func (d *WAFDetector) matchHeaders(res *wscanhttp.Response, headerPattern, valuePattern string) (bool, string) {
	// Try exact header name match first
	headerVal := res.Header.Get(headerPattern)
	if headerVal != "" {
		if valuePattern == "" {
			return true, fmt.Sprintf("Header %s present", headerPattern)
		}
		if re, err := regexp.Compile(valuePattern); err == nil && re.MatchString(headerVal) {
			return true, fmt.Sprintf("Header %s=%s matches %q", headerPattern, headerVal, valuePattern)
		}
		// Fallback: literal contains match
		if strings.Contains(strings.ToLower(headerVal), strings.ToLower(valuePattern)) {
			return true, fmt.Sprintf("Header %s contains %q", headerPattern, valuePattern)
		}
	}

	// Try prefix match for headers like "X-Akamai-" that may match multiple headers
	if strings.HasSuffix(headerPattern, "-") {
		prefix := headerPattern
		for k := range res.Header {
			if strings.HasPrefix(k, prefix) {
				return true, fmt.Sprintf("Header %s* present (matched %s)", prefix, k)
			}
		}
	}

	// Try case-insensitive match for the header name
	for k, v := range res.Header {
		if strings.EqualFold(k, headerPattern) {
			if valuePattern == "" {
				return true, fmt.Sprintf("Header %s present", k)
			}
			for _, val := range v {
				if re, err := regexp.Compile(valuePattern); err == nil && re.MatchString(val) {
					return true, fmt.Sprintf("Header %s=%s matches %q", k, val, valuePattern)
				}
				if strings.Contains(strings.ToLower(val), strings.ToLower(valuePattern)) {
					return true, fmt.Sprintf("Header %s contains %q", k, valuePattern)
				}
			}
		}
	}

	return false, ""
}

// matchCookies checks if response cookies match fingerprint cookie patterns
func (d *WAFDetector) matchCookies(res *wscanhttp.Response, cookiePatterns []string) (bool, string) {
	var cookies []*http.Cookie
	if res.NativeResponse != nil {
		cookies = res.Cookies()
	}
	if len(cookies) == 0 {
		// Try to extract cookie names from Set-Cookie headers as fallback
		for _, setCookie := range res.Header.Values("Set-Cookie") {
			parts := strings.SplitN(setCookie, "=", 2)
			if len(parts) > 0 {
				cookies = append(cookies, &http.Cookie{Name: parts[0]})
			}
		}
	}
	if len(cookies) == 0 {
		return false, ""
	}

	for _, pattern := range cookiePatterns {
		cookieRe, err := regexp.Compile(pattern)
		for _, cookie := range cookies {
			if err != nil {
				// Not a valid regex, try literal/contains match
				if strings.Contains(cookie.Name, pattern) ||
					strings.HasPrefix(cookie.Name, pattern) {
					return true, fmt.Sprintf("Cookie %s matches pattern %q", cookie.Name, pattern)
				}
				continue
			}
			if cookieRe.MatchString(cookie.Name) {
				return true, fmt.Sprintf("Cookie %s matches pattern %q", cookie.Name, pattern)
			}
		}
	}

	return false, ""
}

// matchBodyPatterns checks if response body matches fingerprint body patterns
func (d *WAFDetector) matchBodyPatterns(res *wscanhttp.Response, bodyPatterns []string) (bool, string) {
	body := res.Text
	if body == "" {
		return false, ""
	}

	for _, pattern := range bodyPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			// Not a valid regex, try literal contains match
			if strings.Contains(body, pattern) {
				return true, fmt.Sprintf("Body contains %q", pattern)
			}
			continue
		}
		if re.MatchString(body) {
			return true, fmt.Sprintf("Body matches pattern %q", pattern)
		}
	}

	return false, ""
}

// getBlockStatusCodes returns the block status codes from config
func (d *WAFDetector) getBlockStatusCodes() []int {
	if d.cfg != nil && len(d.cfg.BlockStatusCodes) > 0 {
		return d.cfg.BlockStatusCodes
	}
	return []int{403}
}

// bodyHash computes a SHA256 hash of the response body for comparison
func bodyHash(body string) string {
	h := sha256.Sum256([]byte(body))
	return fmt.Sprintf("%x", h[:8])
}

// abs returns the absolute value of an integer
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// WAFFinger implements base.FingerFactory for the built-in WAF detection
type WAFFinger struct {
	cfg *Config
}

// NewWAFFinger creates a new WAF detection finger
func NewWAFFinger(cfg *Config) *WAFFinger {
	return &WAFFinger{cfg: cfg}
}

// Run executes WAF detection against the target
func (w *WAFFinger) Run(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	if flow == nil || flow.Request == nil {
		return nil
	}

	targetURL := flow.Request.URL().String()
	detector := NewWAFDetector(w.cfg)

	var bestResult *WAFDetectionResult

	// Method 1: Passive detection on existing response
	if flow.Response != nil {
		if passiveResult := detector.DetectPassive(flow.Response); passiveResult != nil {
			bestResult = passiveResult
			logger.Infof("WAF detected (passive): %s (confidence: %d%%, evidence: %s)",
				passiveResult.Name, passiveResult.Confidence, passiveResult.Evidence)
		}
	}

	// Method 2: Active probing (if enabled)
	if w.cfg.ActiveProbe {
		if activeResult := detector.DetectActive(ctx, ab, targetURL); activeResult != nil {
			if bestResult == nil || activeResult.Confidence > bestResult.Confidence {
				bestResult = activeResult
				logger.Infof("WAF detected (active): %s (confidence: %d%%, evidence: %s)",
					activeResult.Name, activeResult.Confidence, activeResult.Evidence)
			}
		}
	}

	// Report WAF detection as a finding
	if bestResult != nil && bestResult.Detected {
		wafReq := flow.Request
		wafRes := flow.Response
		if wafRes == nil {
			// Send a baseline request to get a response for the vuln report
			res, err := ab.HTTPClient.Respond(ctx, wafReq)
			if err != nil {
				return nil
			}
			wafRes = res
		}

		v := ab.NewWebVuln(wafReq, wafRes, nil)
		if v != nil {
			v.SetTargetURL(wafReq.URL())
			// Add WAF details to vulnerability
			bypassStr := ""
			if len(bestResult.BypassTips) > 0 {
				bypassStr = "\n\nBypass suggestions:\n"
				for i, tip := range bestResult.BypassTips {
					bypassStr += fmt.Sprintf("  %d. %s\n", i+1, tip)
				}
			}
			detail := fmt.Sprintf("WAF Detected: %s (Vendor: %s, Category: %s)\n"+
				"Detection Method: %s\nConfidence: %d%%\nEvidence: %s%s",
				bestResult.Name, bestResult.Vendor, bestResult.Category,
				bestResult.Method, bestResult.Confidence, bestResult.Evidence, bypassStr)
			v.Add("waf_name", bestResult.Name)
			v.Add("waf_vendor", bestResult.Vendor)
			v.Add("waf_category", bestResult.Category)
			v.Add("waf_method", bestResult.Method)
			v.Add("waf_confidence", fmt.Sprintf("%d", bestResult.Confidence))
			v.Add("waf_evidence", bestResult.Evidence)
			v.AddStringArray("waf_bypass_tips", bestResult.BypassTips)
			v.Payload = detail
			ab.OutputVuln(v)
		}
	}

	return nil
}

// Finger returns base.Finger for WAF detection
func (w *WAFFinger) Finger() *base.Finger {
	return &base.Finger{
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "waf/detection",
			Plugin:   "waftest",
			Category: "waf",
			Severity: model.SeverityInfo,
		},
		ExecAction: w.Run,
	}
}
