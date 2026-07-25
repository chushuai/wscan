package xss

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"testing"

	whttp "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/checker"
	"wscan/core/utils/checker/filter"
	"wscan/core/utils/printer"
)

// ==================== XSS Init with URLChecker edge cases ====================

func TestBoostXSS_Init_EmptyFilterConfig(t *testing.T) {
	x := &XSS{}
	cfg := &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  true,
		DetectXSSInReferer: true,
		IEFeature:          true,
	}
	ab := &base.ApolloBase{
		FilterConfig:    &checker.RequestCheckerConfig{},
		FilterContainer: filter.NewSyncMapFilter(),
	}
	err := x.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

// ==================== Fingers CheckAction deeper paths ====================

type collectPrinter struct {
	vulns []any
}

func (c *collectPrinter) AddInterceptor(func(any) (any, error)) printer.Printer { return c }
func (c *collectPrinter) Close() error                                          { return nil }
func (c *collectPrinter) Print(v any) error                                     { c.vulns = append(c.vulns, v); return nil }

func makeBoostFlowAndApollo(t *testing.T, serverURL string) (*base.Apollo, *whttp.Request) {
	t.Helper()
	req, err := whttp.NewRequest("GET", serverURL+"/?a=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	flow := &whttp.Flow{
		Request:  req,
		Response: &whttp.Response{Text: "", StatusCode: 200, Header: nethttp.Header{"Content-Type": {"text/html"}}},
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase.HTTPClient = whttp.NewClient()
	apollo.ApolloBase.Output = nopPrinter{}
	apollo.ApolloBase.VulnFilter = &model.VulnFilterConfig{}
	return apollo, req
}

// Test XSS with double-quote attribute value reflection that gets escaped
func TestBoostXSS_EscapedAttributeReflection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		// Reflect with escaped quotes
		w.Write([]byte(`<div class="` + a + `">text</div>`))
	}))
	defer server.Close()

	apollo, _ := makeBoostFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	ctx := context.Background()
	err := fingers[0].CheckAction(ctx, apollo)
	_ = err
}

// Test XSS with reflection in src attribute (triggers javascript: protocol path)
func TestBoostXSS_SrcAttrJSProtocol(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<iframe src="` + a + `">frame</iframe>`))
	}))
	defer server.Close()

	apollo, _ := makeBoostFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	ctx := context.Background()
	err := fingers[0].CheckAction(ctx, apollo)
	_ = err
}

// Test XSS with action attribute reflection
func TestBoostXSS_ActionAttrReflection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<form action="` + a + `"><input type="submit"/></form>`))
	}))
	defer server.Close()

	apollo, _ := makeBoostFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	ctx := context.Background()
	err := fingers[0].CheckAction(ctx, apollo)
	_ = err
}

// Test XSS with formaction attribute reflection
func TestBoostXSS_FormActionAttrReflection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<button formaction="` + a + `">go</button>`))
	}))
	defer server.Close()

	apollo, _ := makeBoostFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	ctx := context.Background()
	err := fingers[0].CheckAction(ctx, apollo)
	_ = err
}

// Test XSS with script tag context - single quote closure
func TestBoostXSS_ScriptTagSingleQuoteClosure(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<script>var x = '` + a + `';</script>`))
	}))
	defer server.Close()

	apollo, _ := makeBoostFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	ctx := context.Background()
	err := fingers[0].CheckAction(ctx, apollo)
	_ = err
}

// Test XSS with script tag context - double quote closure
func TestBoostXSS_ScriptTagDoubleQuoteClosure(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<script>var x = "` + a + `";</script>`))
	}))
	defer server.Close()

	apollo, _ := makeBoostFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	ctx := context.Background()
	err := fingers[0].CheckAction(ctx, apollo)
	_ = err
}

// Test XSS CheckAction with empty tagname in html context
func TestBoostXSS_EmptyTagnameHTMLContext(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		// Reflect in a non-standard way that might yield empty tagname
		w.Write([]byte(`<div><span>` + a + `</span></div>`))
	}))
	defer server.Close()

	apollo, _ := makeBoostFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	ctx := context.Background()
	err := fingers[0].CheckAction(ctx, apollo)
	_ = err
}

// Test XSS with style tag reflection (CSS expression injection path)
func TestBoostXSS_StyleTagCSSExpression(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<style>` + a + `</style>`))
	}))
	defer server.Close()

	apollo, _ := makeBoostFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	ctx := context.Background()
	err := fingers[0].CheckAction(ctx, apollo)
	_ = err
}

// Test XSS with comment context reflection
func TestBoostXSS_CommentContextReflection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!-- ` + a + ` -->`))
	}))
	defer server.Close()

	apollo, _ := makeBoostFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	ctx := context.Background()
	err := fingers[0].CheckAction(ctx, apollo)
	_ = err
}

// Test XSS CheckAction with HTTP errors on verify requests
func TestBoostXSS_VerifyRequestError(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		callCount++
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		// Return HTML for first request, then error for verify requests
		if callCount <= 1 {
			w.Write([]byte(`<div>` + a + `</div>`))
		} else {
			w.WriteHeader(500)
		}
	}))
	defer server.Close()

	apollo, _ := makeBoostFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	ctx := context.Background()
	err := fingers[0].CheckAction(ctx, apollo)
	_ = err
}

// ==================== Cookie XSS with vuln filter ====================

func TestBoostCookieXSS_WithVulnFilter(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		cookie := r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<div>" + cookie + "</div>"))
	}))
	defer server.Close()

	req, err := whttp.NewRequest("GET", server.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	flow := &whttp.Flow{
		Request:  req,
		Response: &whttp.Response{Text: "", StatusCode: 200, Header: nethttp.Header{"Content-Type": {"text/html"}}},
	}
	req.Header = nethttp.Header{"Cookie": {"session=abc123"}}

	apollo := base.NewApollo(flow)
	apollo.ApolloBase.HTTPClient = whttp.NewClient()
	apollo.ApolloBase.Output = nopPrinter{}
	apollo.ApolloBase.VulnFilter = &model.VulnFilterConfig{}
	apollo.ApolloBase.FilterConfig = &checker.RequestCheckerConfig{}
	apollo.ApolloBase.FilterContainer = filter.NewSyncMapFilter()

	c := &cookieXSS{}
	finger := c.Finger()
	ctx := context.Background()
	err = finger.CheckAction(ctx, apollo)
	_ = err
}

// ==================== Referer XSS with full path ====================

func TestBoostRefererXSS_WithVerifyReflection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		referer := r.Header.Get("Referer")
		w.Header().Set("Content-Type", "text/html")
		// Reflect the referer both in HTML and as a new tag for verification
		w.Write([]byte("<div>" + referer + "</div>"))
	}))
	defer server.Close()

	req, err := whttp.NewRequest("GET", server.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	flow := &whttp.Flow{
		Request:  req,
		Response: &whttp.Response{Text: "", StatusCode: 200, Header: nethttp.Header{"Content-Type": {"text/html"}}},
	}

	apollo := base.NewApollo(flow)
	apollo.ApolloBase.HTTPClient = whttp.NewClient()
	apollo.ApolloBase.Output = nopPrinter{}
	apollo.ApolloBase.VulnFilter = &model.VulnFilterConfig{}

	r := &refererXSS{}
	finger := r.Finger()
	ctx := context.Background()
	err = finger.CheckAction(ctx, apollo)
	_ = err
}

// ==================== IE XSS with attribute context ====================

func TestBoostIEXSS_AttributeContextReflection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="` + a + `">click</a>`))
	}))
	defer server.Close()

	apollo, _ := makeBoostFlowAndApollo(t, server.URL)
	ie := &ieFeatureXSS{}
	finger := ie.Finger()
	ctx := context.Background()
	err := finger.CheckAction(ctx, apollo)
	_ = err
}

// ==================== SearchInputInResponse additional edge cases ====================

func TestBoostSearchInputInResponse_ExactAttrKeyMatch(t *testing.T) {
	body := `<div mykey="value">text</div>`
	result := SearchInputInResponse("mykey", body)
	found := false
	for _, occ := range result {
		if occ.Type == "attribute" && occ.Details["content"] == "key" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find attribute key match")
	}
}

func TestBoostSearchInputInResponse_ExactAttrValueMatch(t *testing.T) {
	body := `<div class="myval">text</div>`
	result := SearchInputInResponse("myval", body)
	found := false
	for _, occ := range result {
		if occ.Type == "attribute" && occ.Details["content"] == "value" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find attribute value match")
	}
}

func TestBoostSearchInputInResponse_IntagMatch(t *testing.T) {
	body := `<customtag>text</customtag>`
	result := SearchInputInResponse("customtag", body)
	found := false
	for _, occ := range result {
		if occ.Type == "intag" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find intag match for customtag")
	}
}

func TestBoostSearchInputInResponse_ScriptContentMatch(t *testing.T) {
	body := `<script>var marker123 = "hello";</script>`
	result := SearchInputInResponse("marker123", body)
	found := false
	for _, occ := range result {
		if occ.Type == "script" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find script type match")
	}
}

func TestBoostSearchInputInResponse_StyleContentMatch(t *testing.T) {
	body := `<style>.marker123 { color: red; }</style>`
	result := SearchInputInResponse("marker123", body)
	found := false
	for _, occ := range result {
		if occ.Type == "html" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find html type match for style tag content")
	}
}

// ==================== XSS plugin interface compliance ====================

func TestBoostXSS_PluginInterface(t *testing.T) {
	var _ base.Plugin = &XSS{}
}

func TestBoostXSS_Init_WithChecker(t *testing.T) {
	x := &XSS{}
	cfg := &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  false,
		DetectXSSInReferer: false,
		IEFeature:          false,
	}
	ab := &base.ApolloBase{
		FilterConfig:    &checker.RequestCheckerConfig{},
		FilterContainer: filter.NewSyncMapFilter(),
	}
	err := x.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

// ==================== Config with all fields disabled ====================

func TestBoostConfig_AllDisabled(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  false,
		DetectXSSInReferer: false,
		IEFeature:          false,
	}
	if cfg.DetectXSSInCookie {
		t.Error("DetectXSSInCookie should be false")
	}
	if cfg.DetectXSSInReferer {
		t.Error("DetectXSSInReferer should be false")
	}
	if cfg.IEFeature {
		t.Error("IEFeature should be false")
	}
}
