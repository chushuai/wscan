/**
* @Author: PostScan Mechanism
* @Date: 6/16/2026
* PostScan verifies whether injected payloads were persisted after the main
* scan completes. It re-visits reflection points to detect stored XSS,
* stored SQLi, and stored RCE (via OOB callbacks).
 */
package base

import (
	"context"
	"fmt"
	"strings"
	"time"
	vhttp "wscan/core/http"
	"wscan/core/model"
	logger "wscan/core/utils/log"
)

// StoredVulnVerifier processes ReflectionRecords collected during the main
// scan phase and re-visits URLs to check whether payloads were persisted.
type StoredVulnVerifier struct {
	ab          *ApolloBase
	httpClient  *vhttp.Client
	maxDuration time.Duration
	reverseWait time.Duration
}

// NewStoredVulnVerifier creates a new verifier bound to the given ApolloBase.
func NewStoredVulnVerifier(ab *ApolloBase, maxDuration time.Duration, reverseWait time.Duration) *StoredVulnVerifier {
	return &StoredVulnVerifier{
		ab:          ab,
		httpClient:  ab.HTTPClient,
		maxDuration: maxDuration,
		reverseWait: reverseWait,
	}
}

// VerifyAll runs all stored-vuln verification checks within the given context.
// It respects context cancellation and the configured max_duration.
func (sv *StoredVulnVerifier) VerifyAll(ctx context.Context, records []*ReflectionRecord) {
	if len(records) == 0 {
		logger.Info("[PostScan] No reflection records to verify")
		return
	}

	logger.Infof("[PostScan] Starting stored-vuln verification for %d reflection records (max_duration=%v, reverse_wait=%v)",
		len(records), sv.maxDuration, sv.reverseWait)

	verifiedCount := 0
	storedCount := 0

	for _, rec := range records {
		select {
		case <-ctx.Done():
			logger.Warn("[PostScan] Context cancelled, stopping verification")
			goto done
		default:
		}

		verifiedCount++
		switch rec.VulnType {
		case "xss":
			if sv.VerifyStoredXSS(ctx, rec) {
				storedCount++
			}
		case "sqli":
			if sv.VerifyStoredSQLi(ctx, rec) {
				storedCount++
			}
		case "cmdi":
			if sv.VerifyStoredRCE(ctx, rec) {
				storedCount++
			}
		default:
			logger.Debugf("[PostScan] Unknown vuln type %q for record at %s", rec.VulnType, rec.URL)
		}
	}

done:
	logger.Infof("[PostScan] Verification complete: %d records checked, %d stored vulnerabilities confirmed",
		verifiedCount, storedCount)
}

// VerifyStoredXSS re-visits the URL from a reflection record and checks if
// the payload marker still exists in the response body. If found, the
// vulnerability is reported as a stored XSS with elevated severity.
func (sv *StoredVulnVerifier) VerifyStoredXSS(ctx context.Context, rec *ReflectionRecord) bool {
	logger.Debugf("[PostScan] Verifying stored XSS at %s (payload=%q)", rec.URL, rec.Payload)

	req, err := vhttp.NewRequest("GET", rec.URL, nil)
	if err != nil {
		logger.Debugf("[PostScan] Failed to create request for %s: %v", rec.URL, err)
		return false
	}

	res, err := sv.httpClient.Respond(ctx, req)
	if err != nil {
		logger.Debugf("[PostScan] Failed to re-visit %s: %v", rec.URL, err)
		return false
	}

	// Check if the payload marker is still present in the response
	if res != nil && res.Text != "" && strings.Contains(res.Text, rec.Payload) {
		logger.Infof("[PostScan] Confirmed stored XSS at %s (payload persisted in response)", rec.URL)
		sv.reportStoredVuln(rec, res, "xss/stored/default", model.SeverityCritical,
			"Stored XSS confirmed: payload persisted across requests")
		return true
	}

	return false
}

// VerifyStoredSQLi re-visits the URL and checks for SQL error patterns or
// data markers that indicate the injected SQL payload was stored and later
// executed when the page is rendered.
func (sv *StoredVulnVerifier) VerifyStoredSQLi(ctx context.Context, rec *ReflectionRecord) bool {
	logger.Debugf("[PostScan] Verifying stored SQLi at %s (payload=%q)", rec.URL, rec.Payload)

	req, err := vhttp.NewRequest("GET", rec.URL, nil)
	if err != nil {
		logger.Debugf("[PostScan] Failed to create request for %s: %v", rec.URL, err)
		return false
	}

	res, err := sv.httpClient.Respond(ctx, req)
	if err != nil {
		logger.Debugf("[PostScan] Failed to re-visit %s: %v", rec.URL, err)
		return false
	}

	if res == nil || res.Text == "" {
		return false
	}

	// Check for SQL error patterns indicating stored SQLi
	sqlErrorPatterns := []string{
		"SQL syntax",
		"mysql_fetch",
		"pg_query",
		"ORA-01756",
		"Microsoft OLE DB Provider",
		"Unclosed quotation mark",
		"SQLSTATE[",
	}

	for _, pattern := range sqlErrorPatterns {
		if strings.Contains(res.Text, pattern) {
			logger.Infof("[PostScan] Confirmed stored SQLi at %s (SQL error pattern: %q)", rec.URL, pattern)
			sv.reportStoredVuln(rec, res, "sqldet/stored/default", model.SeverityCritical,
				fmt.Sprintf("Stored SQLi confirmed: SQL error pattern %q found on re-visit", pattern))
			return true
		}
	}

	// Check if the payload marker itself appears (data exfiltration marker)
	if rec.Payload != "" && strings.Contains(res.Text, rec.Payload) {
		logger.Infof("[PostScan] Confirmed stored SQLi at %s (payload marker persisted)", rec.URL)
		sv.reportStoredVuln(rec, res, "sqldet/stored/default", model.SeverityHigh,
			"Stored SQLi confirmed: payload marker persisted across requests")
		return true
	}

	return false
}

// VerifyStoredRCE checks the reverse platform for delayed callbacks that
// indicate a command injection payload was stored and later executed.
// It waits up to reverse_wait seconds for OOB callbacks to arrive.
func (sv *StoredVulnVerifier) VerifyStoredRCE(ctx context.Context, rec *ReflectionRecord) bool {
	logger.Debugf("[PostScan] Verifying stored RCE at %s (reverse_token=%q)", rec.URL, rec.ReverseToken)

	if sv.ab.Reverse == nil || rec.ReverseToken == "" {
		logger.Debugf("[PostScan] Cannot verify stored RCE: no reverse platform or token")
		return false
	}

	// For stored RCE, we wait for the configured reverse_wait period and then
	// check whether the reverse platform received a delayed callback for the
	// original unit. The reverse platform's FetchEvent() goroutine is already
	// polling every 3s, so callbacks will be delivered automatically.
	//
	// The unit callback set during the main scan (via OnVisit) will fire if
	// a stored payload triggers an OOB callback after the main scan. However,
	// since that callback typically calls OutputVuln, the vulnerability will
	// already be reported through the normal path.
	//
	// For PostScan, we additionally wait for the extended reverse_wait window
	// to catch delayed callbacks that arrive well after the main scan ends.
	// This is handled by the extended sleep in the dispatcher's postScanPhase.

	// Wait up to reverse_wait for OOB callbacks
	waitCtx, waitCancel := context.WithTimeout(ctx, sv.reverseWait)
	defer waitCancel()

	select {
	case <-waitCtx.Done():
		// Wait period elapsed without finding additional evidence
	case <-ctx.Done():
		logger.Debug("[PostScan] Context cancelled during RCE verification")
		return false
	}

	// If we reach here, the reverse_wait period has elapsed.
	// Any OOB callbacks during this window would have already been handled
	// by the unit's OnVisit callback from the main scan phase.
	// For a fully robust stored RCE detection, the plugin should record the
	// reverse token in ReflectionRecord and we would query the reverse DB
	// directly. This is a simplified implementation that relies on the
	// extended wait window in the dispatcher.
	logger.Debugf("[PostScan] RCE verification wait complete for %s", rec.URL)
	return false
}

// reportStoredVuln creates and outputs a stored vulnerability with elevated severity.
func (sv *StoredVulnVerifier) reportStoredVuln(rec *ReflectionRecord, res *vhttp.Response, vulnID string, severity model.SeverityLevel, detail string) {
	vuln := &model.Vuln{
		Binding: &model.VulnBinding{
			ID:       vulnID,
			Plugin:   rec.PluginName + "/stored",
			Category: rec.VulnType,
			Severity: severity,
		},
		Extra: map[string]any{
			"stored":      true,
			"detail":      detail,
			"original_id": rec.PluginName,
		},
		CreateTime: time.Now().Unix(),
		Payload:    rec.Payload,
	}

	// Build the request/response flow if available
	if rec.URL != "" {
		req, err := vhttp.NewRequest(rec.Method, rec.URL, nil)
		if err == nil {
			flows := []*vhttp.Flow{{Request: req}}
			if res != nil {
				flows[0].Response = res
			}
			vuln.Flow = flows
			vuln.SetTargetURL(req.URL())
		}
	}

	// Add parameter info if available
	if rec.Parameter != "" {
		vuln.Param = &vhttp.Parameter{
			Position: "query",
			Key:      rec.Parameter,
			Value:    rec.Payload,
		}
	}

	// Output the vulnerability through the standard printer
	if sv.ab.Output != nil {
		sv.ab.Output.Print(vuln)
	}
}
