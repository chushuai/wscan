package path_traversal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	whttp "wscan/core/http"
	"wscan/core/plugins/base"
)

func TestPathTraversalDirect_ExecAction_WithQueryParams(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Query()) > 0 {
			w.WriteHeader(200)
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("normal response"))
	}))
	defer ts.Close()

	p := &PathTraversal{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{
		HTTPClient: whttp.NewClient(),
	}
	p.Init(context.Background(), cfg, ab)

	req, _ := whttp.NewRequest("GET", ts.URL+"/page?file=test.txt", nil)
	flow := &whttp.Flow{
		Request:  req,
		Response: &whttp.Response{StatusCode: 200},
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase = ab

	fingers := p.Fingers()
	if len(fingers) == 0 {
		t.Fatal("expected at least one finger")
	}
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

func TestPathTraversalDirect_ExecAction_NoParams(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	p := &PathTraversal{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{
		HTTPClient: whttp.NewClient(),
	}
	p.Init(context.Background(), cfg, ab)

	req, _ := whttp.NewRequest("GET", ts.URL+"/page", nil)
	flow := &whttp.Flow{
		Request:  req,
		Response: &whttp.Response{StatusCode: 200},
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase = ab

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Errorf("execAction with no params returned error: %v", err)
	}
}

func TestPathTraversalDirect_ExecAction_PostBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("normal"))
	}))
	defer ts.Close()

	p := &PathTraversal{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{
		HTTPClient: whttp.NewClient(),
	}
	p.Init(context.Background(), cfg, ab)

	req, _ := whttp.NewRequest("POST", ts.URL+"/page", strings.NewReader("file=test.txt"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	flow := &whttp.Flow{
		Request:  req,
		Response: &whttp.Response{StatusCode: 200},
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase = ab

	fingers := p.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	if err != nil {
		t.Logf("execAction returned error: %v", err)
	}
}

func TestPathTraversalDirect_IsValueReplacePayload(t *testing.T) {
	tests := []struct {
		vector   string
		expected bool
	}{
		{"php://filter/resource=/etc/passwd", true},
		{"file:///etc/passwd", true},
		{"file://localhost/etc/passwd", true},
		{"http://evil.com/shell.php", false},
		{"../../etc/passwd", false},
		{"/etc/passwd", false},
		{"", false},
	}
	for _, tt := range tests {
		result := isValueReplacePayload(tt.vector)
		if result != tt.expected {
			t.Errorf("isValueReplacePayload(%q) = %v, expected %v", tt.vector, result, tt.expected)
		}
	}
}

func TestPathTraversalDirect_RulesLoaded(t *testing.T) {
	if len(pathTraversalRules) == 0 {
		t.Error("expected pathTraversalRules to be loaded by init()")
	}
	for i, rule := range pathTraversalRules {
		if rule.compiled == nil {
			t.Errorf("rule[%d] compiled should not be nil", i)
		}
		if rule.typ == "" {
			t.Errorf("rule[%d] typ should not be empty", i)
		}
	}
}

func TestPathTraversalDirect_RuleTypes(t *testing.T) {
	foundLFI := false
	foundRFI := false
	foundFI := false
	for _, rule := range pathTraversalRules {
		switch rule.typ {
		case "LFI":
			foundLFI = true
		case "RFI":
			foundRFI = true
		case "FI":
			foundFI = true
		}
	}
	if !foundLFI {
		t.Error("expected at least one LFI rule")
	}
	if !foundRFI {
		t.Error("expected at least one RFI rule")
	}
	if !foundFI {
		t.Error("expected at least one FI rule")
	}
}
