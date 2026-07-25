package fingerprint

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	wscan_http "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/plugins/helper/knowledge"
	"wscan/core/resource"
	"wscan/core/utils/printer"
)

func TestProcessFingerprint_Coverage(t *testing.T) {
	ProcessFingerprint(context.Background(), &resource.Service{})
}

// Test execAction with a real flow
func TestFingerprint_ExecAction_WithFlow(t *testing.T) {
	p := &Fingerprint{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	// Create a mock Apollo with a flow
	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("<html><body>ok</body></html>")),
		Request:    &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	vulnFound := false
	a.ApolloBase.Output = &mockFPPrinter{onPrint: func(v *model.Vuln) {
		vulnFound = true
	}}
	a.ApolloBase.KDB = knowledge.NewKnowledgeDB(nil)

	err := p.execAction(context.Background(), a)
	_ = err
	_ = vulnFound
}

// Test execAction with nil KDB - just ensure no panic
func TestFingerprint_ExecAction_NilKDB(t *testing.T) {
	p := &Fingerprint{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{}
	p.Init(context.Background(), cfg, ab)

	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 404,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("Not Found")),
		Request:    &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})
	a.ApolloBase.Output = &mockFPPrinter{}

	p.execAction(context.Background(), a)
}

type mockFPPrinter struct {
	onPrint func(v *model.Vuln)
}

func (m *mockFPPrinter) Print(v any) error {
	if vuln, ok := v.(*model.Vuln); ok && m.onPrint != nil {
		m.onPrint(vuln)
	}
	return nil
}
func (m *mockFPPrinter) Close() error                                          { return nil }
func (m *mockFPPrinter) AddInterceptor(func(any) (any, error)) printer.Printer { return m }
func (m *mockFPPrinter) LogSubdomain(any) error                                { return nil }
func (m *mockFPPrinter) LogVuln(any) error                                     { return nil }

// Test FingerprintRule struct
func TestFingerprintRule_Struct(t *testing.T) {
	r := FingerprintRule{
		Engine: "wscan",
		Info:   FingerprintInfo{Name: "test", Author: "test"},
		Pscan:  FingerprintPscan{Path: []string{"/"}, Expressions: []string{"response.status == 200"}},
	}
	if r.Info.Name != "test" {
		t.Errorf("FingerprintRule.Info.Name = %q, want %q", r.Info.Name, "test")
	}
}
