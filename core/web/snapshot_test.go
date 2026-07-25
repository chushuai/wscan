/**
* @Author: shaochuyu
* @Date: 7/25/2026
*
* Verifies that webVulnToFront exposes a parsed request/response snapshot to
* the SPA so the vuln detail pane can render the HTTP traffic.
 */
package web

import (
	"strings"
	"testing"

	"wscan/core/model"
)

// A WebVuln whose snapshot carries a raw HTTP request+response pair (the shape
// produced by model.Vuln.ToWebVuln: []string{reqDump, resDump}) should surface
// as structured request/response objects the front end's httpSec() understands.
func TestWebVulnToFrontSnapshot(t *testing.T) {
	reqDump := "GET /a?x=<script> HTTP/1.1\r\nHost: example.com\r\nUser-Agent: t\r\n\r\n"
	resDump := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 4\r\n\r\nbody"

	v := &model.WebVuln{
		Plugin:   "xss",
		Severity: model.SeverityHigh,
		Target:   model.WebTarget{URL: "http://example.com/a"},
		Detail: model.VulnDetail{
			Addr:     "http://example.com/a?x=<script>",
			Payload:  "<script>",
			SnapShot: []any{[]string{reqDump, resDump}},
		},
	}

	row := webVulnToFront(v)

	req, ok := row["request"].(map[string]any)
	if !ok {
		t.Fatalf("request not surfaced: %#v", row["request"])
	}
	if req["method"] != "GET" {
		t.Fatalf("method: %v", req["method"])
	}
	if !strings.Contains(req["uri"].(string), "/a") {
		t.Fatalf("uri: %v", req["uri"])
	}
	if req["version"] != "HTTP/1.1" {
		t.Fatalf("version: %v", req["version"])
	}
	hdr, ok := req["headers"].(map[string]any)
	if !ok || hdr["Host"] != "example.com" {
		t.Fatalf("request headers missing Host: %#v", req["headers"])
	}

	res, ok := row["response"].(map[string]any)
	if !ok {
		t.Fatalf("response not surfaced: %#v", row["response"])
	}
	if res["status"].(int) != 200 {
		t.Fatalf("status: %v", res["status"])
	}
	if res["body"] != "body" {
		t.Fatalf("response body: %v", res["body"])
	}

	if row["attackVector"] != "<script>" {
		t.Fatalf("attackVector: %v", row["attackVector"])
	}
}

// A WebVuln with no snapshot should not set request/response keys (the pane
// then degrades gracefully — no HTTP section rendered).
func TestWebVulnToFrontNoSnapshot(t *testing.T) {
	v := &model.WebVuln{
		Plugin: "xss",
		Target: model.WebTarget{URL: "http://example.com"},
	}
	row := webVulnToFront(v)
	if _, exists := row["request"]; exists {
		t.Fatalf("request should be absent without a snapshot")
	}
	if _, exists := row["response"]; exists {
		t.Fatalf("response should be absent without a snapshot")
	}
}
