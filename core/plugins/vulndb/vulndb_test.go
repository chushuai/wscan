/**
* @Author: shaochuyu
* @Date: 7/25/2026
*
* Verifies the embedded vuln DB loads, aliases resolve plugin Binding.IDs to
* DB entries, and an unknown id returns nil.
 */
package vulndb

import (
	"strings"
	"testing"
)

// The embedded DB should have loaded the generated xml files.
func TestLoaded(t *testing.T) {
	if !Loaded() {
		t.Fatalf("vuln DB is empty; embed did not load any xml files")
	}
	e := Lookup("xss")
	if e == nil {
		t.Fatalf("Lookup(xss) returned nil")
	}
	if !strings.Contains(e.Name, "Scripting") {
		t.Fatalf("xss name unexpected: %q", e.Name)
	}
	if e.Description == "" {
		t.Fatalf("xss description empty")
	}
}

// A plugin Binding.ID with an alias should resolve to the aliased entry.
func TestAliasResolve(t *testing.T) {
	e := Lookup("xss/reflected/default")
	if e == nil {
		t.Fatalf("alias xss/reflected/default did not resolve")
	}
	if !strings.Contains(e.Name, "Scripting") {
		t.Fatalf("alias resolved to wrong entry: %q", e.Name)
	}
	// unknown id returns nil
	if Lookup("no/such/vuln") != nil {
		t.Fatalf("unknown id should return nil")
	}
}

// A hand-written entry should carry its full advisory text.
func TestHandWrittenEntry(t *testing.T) {
	e := Lookup("cookiekey_weak_key")
	if e == nil {
		t.Fatalf("cookiekey_weak_key not found")
	}
	if e.Description == "" || e.Recommendation == "" {
		t.Fatalf("hand-written entry missing text")
	}
	if len(e.References) == 0 {
		t.Fatalf("hand-written entry missing references")
	}
}
