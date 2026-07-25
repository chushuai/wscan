/**
* @Author: shaochyyu
* @Date: 7/25/2026
*
* Verifies the embedded vuln DB loads, aliases resolve plugin Binding.IDs to
* DB entries, and webVulnToFront fills description/impact/recommendation.
 */
package web

import (
	"strings"
	"testing"

	"wscan/core/model"
)

// The embedded DB should have loaded the generated xml files.
func TestVulnDBLoaded(t *testing.T) {
	if len(vulnDB) == 0 {
		t.Fatalf("vulnDB is empty; embed did not load any xml files")
	}
	e := lookupVulnDB("xss")
	if e == nil {
		t.Fatalf("lookupVulnDB(xss) returned nil")
	}
	if !strings.Contains(e.Name, "Scripting") {
		t.Fatalf("xss name unexpected: %q", e.Name)
	}
	if e.Description == "" {
		t.Fatalf("xss description empty")
	}
}

// A plugin Binding.ID with an alias should resolve to the aliased entry.
func TestVulnDBAlias(t *testing.T) {
	e := lookupVulnDB("xss/reflected/default")
	if e == nil {
		t.Fatalf("alias xss/reflected/default did not resolve")
	}
	if !strings.Contains(e.Name, "Scripting") {
		t.Fatalf("alias resolved to wrong entry: %q", e.Name)
	}
	// unknown id returns nil
	if lookupVulnDB("no/such/vuln") != nil {
		t.Fatalf("unknown id should return nil")
	}
}

// webVulnToFront should enrich the row with DB metadata for an aliased id.
func TestWebVulnToFrontEnrichment(t *testing.T) {
	v := &model.WebVuln{
		Plugin:   "xss/reflected",
		Severity: model.SeverityHigh,
		Target:   model.WebTarget{URL: "http://example.com/a"},
		Detail:   model.VulnDetail{Addr: "http://example.com/a?q=x"},
	}
	// force the type id onto the vuln by giving it a plugin name that maps
	// through vulnTypeID -> "xss/reflected" is the plugin; set Binding via a
	// custom plugin string matching the alias key.
	v.Plugin = "xss/reflected/default"
	row := webVulnToFront(v)
	if row["description"] == nil {
		t.Fatalf("description not enriched for aliased id")
	}
	if row["impact"] == nil {
		t.Fatalf("impact not enriched")
	}
	if row["recommendation"] == nil {
		t.Fatalf("recommendation not enriched")
	}
	refs, ok := row["references"].([]map[string]any)
	if !ok || len(refs) == 0 {
		t.Fatalf("references not enriched: %#v", row["references"])
	}
}
