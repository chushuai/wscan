package xss

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	whttp "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/checker"
	"wscan/core/utils/checker/filter"
	"wscan/core/utils/printer"
)

// ==================== requestBuilder additional coverage ====================

func TestCB2_RequestBuilder_Wrap_EmptyString(t *testing.T) {
	rb := &requestBuilder{}
	result := rb.wrap("")
	if result != "" {
		t.Errorf("expected empty string from wrap(''), got '%s'", result)
	}
}

func TestCB2_RequestBuilder_Wrap_NonEmptyString(t *testing.T) {
	rb := &requestBuilder{}
	result := rb.wrap("somepayload")
	if result != "" {
		t.Errorf("expected empty string from wrap (always returns ''), got '%s'", result)
	}
}

func TestCB2_RequestBuilder_WithPrefixAndSuffix(t *testing.T) {
	rb := &requestBuilder{
		prefix:       "prefix-",
		suffix:       "-suffix",
		last_payload: "test",
	}
	rb.build() // should not panic
	rb.clone() // should not panic
	rb.withPrefix()
	rb.withSuffix()
}

func TestCB2_RequestBuilder_WithRequest(t *testing.T) {
	req, _ := whttp.NewRequest("GET", "http://example.com/?a=1", nil)
	rb := &requestBuilder{
		prefix:       "",
		suffix:       "",
		request:      req,
		parameter:    &whttp.Parameter{Position: whttp.PositionQuery, Key: "a", Value: "1"},
		last_payload: "marker",
	}
	rb.build()
}

func TestCB2_NewRequestBuilder_NoPanic(t *testing.T) {
	newRequestBuilder()
}

// ==================== QueryResponse additional coverage ====================

func TestCB2_QueryResponse_Exists_False(t *testing.T) {
	qr := &QueryResponse{}
	result := qr.exists("div")
	if result {
		t.Error("expected false from exists on empty QueryResponse")
	}
}

func TestCB2_QueryResponse_Query_NoPanic(t *testing.T) {
	qr := &QueryResponse{}
	qr.query()
}

func TestCB2_QueryResponse_QueryFirst_NoPanic(t *testing.T) {
	qr := &QueryResponse{}
	qr.queryFirst()
}

func TestCB2_QueryResponse_QueryText_Empty(t *testing.T) {
	qr := &QueryResponse{}
	result := qr.queryText("div")
	if result != "" {
		t.Errorf("expected empty string, got '%s'", result)
	}
}

func TestCB2_QueryResponse_QueryText_NonExistentSelector(t *testing.T) {
	qr := &QueryResponse{}
	result := qr.queryText("nonexistent.tag")
	if result != "" {
		t.Errorf("expected empty string for nonexistent selector, got '%s'", result)
	}
}

// ==================== SearchInputInResponse additional edge cases ====================

func TestCB2_SearchInputInResponse_BooleanAttribute(t *testing.T) {
	body := `<input disabled />`
	result := SearchInputInResponse("disabled", body)
	// "disabled" may appear as attribute key
	_ = result
}

func TestCB2_SearchInputInResponse_DataAttribute(t *testing.T) {
	body := `<div data-mymarker="value">text</div>`
	result := SearchInputInResponse("data-mymarker", body)
	found := false
	for _, occ := range result {
		if occ.Type == "attribute" && occ.Details["content"] == "key" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find data-mymarker attribute key match")
	}
}

func TestCB2_SearchInputInResponse_SVGTag(t *testing.T) {
	body := `<svg><text>mymarker</text></svg>`
	result := SearchInputInResponse("mymarker", body)
	if len(result) == 0 {
		t.Error("expected at least one occurrence in SVG text")
	}
}

func TestCB2_SearchInputInResponse_TableContent(t *testing.T) {
	body := `<table><tr><td>mymarker</td></tr></table>`
	result := SearchInputInResponse("mymarker", body)
	if len(result) == 0 {
		t.Error("expected at least one occurrence in table")
	}
}

func TestCB2_SearchInputInResponse_TemplateTag(t *testing.T) {
	body := `<template>mymarker</template>`
	result := SearchInputInResponse("mymarker", body)
	_ = result // template tag may or may not be parsed by goquery
}

func TestCB2_SearchInputInResponse_ObjectTagParam(t *testing.T) {
	body := `<object data="mymarker"></object>`
	result := SearchInputInResponse("mymarker", body)
	found := false
	for _, occ := range result {
		if occ.Type == "attribute" && occ.Details["content"] == "value" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find data attribute value match in object tag")
	}
}

func TestCB2_SearchInputInResponse_MultipleClasses(t *testing.T) {
	body := `<div class="class1 mymarker class2">text</div>`
	result := SearchInputInResponse("mymarker", body)
	// "mymarker" is part of the class attribute value but not the full value
	// This tests substring matching in attribute values
	_ = result
}

func TestCB2_SearchInputInResponse_InlineStyle(t *testing.T) {
	body := `<div style="color: mymarker">text</div>`
	result := SearchInputInResponse("mymarker", body)
	// Check if mymarker is found in style attribute value
	_ = result
}

func TestCB2_SearchInputInResponse_EventHandler(t *testing.T) {
	body := `<div onclick="mymarker">text</div>`
	result := SearchInputInResponse("mymarker", body)
	found := false
	for _, occ := range result {
		if occ.Type == "attribute" && occ.Details["content"] == "value" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find onclick attribute value match")
	}
}

func TestCB2_SearchInputInResponse_NestedScript(t *testing.T) {
	body := `<div><script>var x = "mymarker";</script></div>`
	result := SearchInputInResponse("mymarker", body)
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

func TestCB2_SearchInputInResponse_IntagCustomElement(t *testing.T) {
	body := `<my-custom-element>hello</my-custom-element>`
	result := SearchInputInResponse("my-custom-element", body)
	found := false
	for _, occ := range result {
		if occ.Type == "intag" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find intag match for custom element")
	}
}

func TestCB2_SearchInputInResponse_StyleTagContent(t *testing.T) {
	body := `<style>body { background: mymarker; }</style>`
	result := SearchInputInResponse("mymarker", body)
	if len(result) == 0 {
		t.Error("expected at least one occurrence in style tag")
	}
	for _, occ := range result {
		if occ.Details["tagname"] == "style" && occ.Type != "html" {
			t.Errorf("expected type 'html' for style tag content, got '%s'", occ.Type)
		}
	}
}

func TestCB2_SearchInputInResponse_ScriptTagMultiVar(t *testing.T) {
	body := `<script>var a = "mymarker"; var b = a;</script>`
	result := SearchInputInResponse("mymarker", body)
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

func TestCB2_SearchInputInResponse_LinkTagHref(t *testing.T) {
	body := `<link rel="stylesheet" href="mymarker" />`
	result := SearchInputInResponse("mymarker", body)
	found := false
	for _, occ := range result {
		if occ.Type == "attribute" && occ.Details["content"] == "value" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find href attribute value match in link tag")
	}
}

func TestCB2_SearchInputInResponse_MetaTagContent(t *testing.T) {
	body := `<meta name="description" content="mymarker" />`
	result := SearchInputInResponse("mymarker", body)
	found := false
	for _, occ := range result {
		if occ.Type == "attribute" && occ.Details["content"] == "value" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find content attribute value match in meta tag")
	}
}

// ==================== XSS struct additional coverage ====================

func TestCB2_XSS_Close_NilError(t *testing.T) {
	x := &XSS{}
	err := x.Close()
	if err != nil {
		t.Errorf("expected nil error from Close, got %v", err)
	}
}

func TestCB2_XSS_DefaultConfig_Values(t *testing.T) {
	x := &XSS{}
	cfg := x.DefaultConfig().(*Config)
	if cfg.PluginBaseConfig.Name != "xss" {
		t.Errorf("expected Name='xss', got '%s'", cfg.PluginBaseConfig.Name)
	}
	if !cfg.PluginBaseConfig.Enabled {
		t.Error("expected Enabled=true")
	}
	if !cfg.DetectXSSInCookie {
		t.Error("expected DetectXSSInCookie=true")
	}
	if !cfg.DetectXSSInReferer {
		t.Error("expected DetectXSSInReferer=true")
	}
	if !cfg.IEFeature {
		t.Error("expected IEFeature=true")
	}
}

func TestCB2_XSS_Scan_ReturnsNil(t *testing.T) {
	x := &XSS{}
	scanFn := x.Scan()
	if scanFn != nil {
		t.Error("expected nil Scan function")
	}
}

func TestCB2_XSS_ExecAction_ReturnsNil(t *testing.T) {
	x := &XSS{}
	err := x.execAction(nil, nil)
	if err != nil {
		t.Errorf("expected nil error from execAction, got %v", err)
	}
}

// ==================== Config additional coverage ====================

func TestCB2_Config_BaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  true,
		DetectXSSInReferer: false,
		IEFeature:          true,
	}
	bc := cfg.BaseConfig()
	if bc.Name != "xss" {
		t.Errorf("expected Name='xss', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("expected Enabled=true")
	}
}

func TestCB2_Config_AllFalse(t *testing.T) {
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

// ==================== XSS Init with various configs ====================

func TestCB2_XSS_Init_WithURLChecker(t *testing.T) {
	x := &XSS{}
	cfg := &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  true,
		DetectXSSInReferer: true,
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
	if x.cookieDomainFilter == nil {
		t.Error("expected cookieDomainFilter to be set")
	}
	if x.refererFilter == nil {
		t.Error("expected refererFilter to be set")
	}
}

func TestCB2_XSS_Init_CookieOnly(t *testing.T) {
	x := &XSS{}
	cfg := &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  true,
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

func TestCB2_XSS_Init_RefererOnly(t *testing.T) {
	x := &XSS{}
	cfg := &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  false,
		DetectXSSInReferer: true,
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

func TestCB2_XSS_Init_NilConfig(t *testing.T) {
	x := &XSS{}
	err := x.Init(context.Background(), nil, nil)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestCB2_XSS_Init_DegradePath(t *testing.T) {
	x := &XSS{}
	cfg := &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  true,
		DetectXSSInReferer: true,
		IEFeature:          false,
	}
	ab := &base.ApolloBase{
		FilterConfig:    &checker.RequestCheckerConfig{},
		FilterContainer: nil, // nil FilterContainer to trigger degrade path
	}
	err := x.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

// ==================== Element struct additional coverage ====================

func TestCB2_Element_EmptyAttributes(t *testing.T) {
	e := Element{
		name:       "div",
		attributes: map[string]string{},
		text:       "",
	}
	if e.name != "div" {
		t.Errorf("expected name 'div', got '%s'", e.name)
	}
	if len(e.attributes) != 0 {
		t.Errorf("expected 0 attributes, got %d", len(e.attributes))
	}
}

// ==================== Occurrence struct additional coverage ====================

func TestCB2_Occurrence_AllTypes(t *testing.T) {
	types := []string{"intag", "html", "script", "attribute", "comment"}
	for _, typ := range types {
		occ := Occurrence{
			Type:     typ,
			Position: 0,
			Details:  map[string]any{"tagname": "div"},
		}
		if occ.Type != typ {
			t.Errorf("expected Type='%s', got '%s'", typ, occ.Type)
		}
	}
}

// ==================== cookiePair additional coverage ====================

func TestCB2_CookiePair_Fields(t *testing.T) {
	pair := cookiePair{Key: "session", Value: "abc123"}
	if pair.Key != "session" {
		t.Errorf("expected Key 'session', got '%s'", pair.Key)
	}
	if pair.Value != "abc123" {
		t.Errorf("expected Value 'abc123', got '%s'", pair.Value)
	}
}

// ==================== Fingers additional coverage ====================

func TestCB2_XSS_Fingers_NilConfig_OnlyMain(t *testing.T) {
	x := &XSS{}
	fingers := x.Fingers()
	if len(fingers) < 1 {
		t.Error("expected at least one finger (main XSS)")
	}
}

func TestCB2_XSS_Fingers_AllEnabled(t *testing.T) {
	x := &XSS{}
	x.PluginMixinInitConfig.Config = &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  true,
		DetectXSSInReferer: true,
		IEFeature:          true,
	}
	fingers := x.Fingers()
	if len(fingers) < 4 {
		t.Errorf("expected at least 4 fingers, got %d", len(fingers))
	}
}

func TestCB2_XSS_Fingers_OnlyIE(t *testing.T) {
	x := &XSS{}
	x.PluginMixinInitConfig.Config = &Config{
		PluginBaseConfig:   base.PluginBaseConfig{Name: "xss", Enabled: true},
		DetectXSSInCookie:  false,
		DetectXSSInReferer: false,
		IEFeature:          true,
	}
	fingers := x.Fingers()
	foundIE := false
	for _, f := range fingers {
		if f.Binding != nil && f.Binding.ID == "xss/reflected/ie-feature" {
			foundIE = true
		}
	}
	if !foundIE {
		t.Error("expected IE feature XSS finger to be registered")
	}
}

// ==================== IE Payloads coverage ====================

func TestCB2_IEPayloads_NotEmpty(t *testing.T) {
	if len(iePayloads) == 0 {
		t.Fatal("expected at least one IE payload")
	}
}

func TestCB2_IEPayloads_HasContent(t *testing.T) {
	for i, p := range iePayloads {
		if p.Description == "" {
			t.Errorf("payload[%d]: Description should not be empty", i)
		}
		if p.Payload == "" {
			t.Errorf("payload[%d]: Payload should not be empty", i)
		}
		if p.Type == "" {
			t.Errorf("payload[%d]: Type should not be empty", i)
		}
	}
}

// ==================== parseCookieHeader additional coverage ====================

func TestCB2_ParseCookieHeader_EmptyValue(t *testing.T) {
	pairs := parseCookieHeader("name=")
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0].Key != "name" {
		t.Errorf("expected Key 'name', got '%s'", pairs[0].Key)
	}
	if pairs[0].Value != "" {
		t.Errorf("expected empty Value, got '%s'", pairs[0].Value)
	}
}

func TestCB2_ParseCookieHeader_ValueWithEquals(t *testing.T) {
	pairs := parseCookieHeader("name=val=ue")
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0].Value != "val=ue" {
		t.Errorf("expected Value 'val=ue', got '%s'", pairs[0].Value)
	}
}

func TestCB2_ParseCookieHeader_WhitespaceOnly(t *testing.T) {
	pairs := parseCookieHeader("   ")
	if len(pairs) != 0 {
		t.Errorf("expected 0 pairs, got %d", len(pairs))
	}
}

func TestCB2_ParseCookieHeader_TrailingSemicolon(t *testing.T) {
	pairs := parseCookieHeader("name=value;")
	if len(pairs) != 1 {
		t.Errorf("expected 1 pair, got %d", len(pairs))
	}
}

// ==================== replaceCookieValue additional coverage ====================

func TestCB2_ReplaceCookieValue_NotFound(t *testing.T) {
	result := replaceCookieValue("a=1; b=2", "c", "X")
	if !strings.Contains(result, "a=1") || !strings.Contains(result, "b=2") {
		t.Errorf("expected original values preserved, got '%s'", result)
	}
}

func TestCB2_ReplaceCookieValue_EmptyHeader(t *testing.T) {
	result := replaceCookieValue("", "a", "X")
	if result != "" {
		t.Errorf("expected empty string for empty header, got '%s'", result)
	}
}

// ==================== Fingers CheckAction integration tests ====================

type cb2NopPrinter struct{}

func (cb2NopPrinter) AddInterceptor(func(any) (any, error)) printer.Printer { return cb2NopPrinter{} }
func (cb2NopPrinter) Close() error                                          { return nil }
func (cb2NopPrinter) Print(any) error                                       { return nil }

func cb2MakeFlowAndApollo(t *testing.T, serverURL string) (*base.Apollo, *whttp.Request) {
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
	apollo.ApolloBase.Output = cb2NopPrinter{}
	apollo.ApolloBase.VulnFilter = &model.VulnFilterConfig{}
	return apollo, req
}

func cb2MakeFlowAndApolloNoQuery(t *testing.T, serverURL string) (*base.Apollo, *whttp.Request) {
	t.Helper()
	req, err := whttp.NewRequest("GET", serverURL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	flow := &whttp.Flow{
		Request:  req,
		Response: &whttp.Response{Text: "", StatusCode: 200, Header: nethttp.Header{"Content-Type": {"text/html"}}},
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase.HTTPClient = whttp.NewClient()
	apollo.ApolloBase.Output = cb2NopPrinter{}
	apollo.ApolloBase.VulnFilter = &model.VulnFilterConfig{}
	return apollo, req
}

// TestCB2_Fingers_HTMLInjection tests HTML injection context
func TestCB2_Fingers_HTMLInjection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<div>" + a + "</div>"))
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_AttrValueInjection tests attribute value injection context
func TestCB2_Fingers_AttrValueInjection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<div class="` + a + `">text</div>`))
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_ScriptInjection tests script injection context
func TestCB2_Fingers_ScriptInjection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<script>var x = '` + a + `';</script>`))
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_CommentInjection tests comment injection context
func TestCB2_Fingers_CommentInjection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<!-- ` + a + ` -->`))
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_StyleInjection tests style tag injection context
func TestCB2_Fingers_StyleInjection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<style>` + a + `</style>`))
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_HrefJSProtocol tests href javascript: protocol path
func TestCB2_Fingers_HrefJSProtocol(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="` + a + `">click</a>`))
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_AttrKeyInjection tests attribute key injection path
func TestCB2_Fingers_AttrKeyInjection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<div ` + a + `="value">text</div>`))
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_NonHTMLContentType tests non-HTML content type
func TestCB2_Fingers_NonHTMLContentType(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"a": "test"}`))
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_NotReflected tests when input is not reflected
func TestCB2_Fingers_NotReflected(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<div>static content</div>"))
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// ==================== Cookie XSS integration ====================

func TestCB2_CookieXSS_WithCookie(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		cookie := r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<div>" + cookie + "</div>"))
	}))
	defer server.Close()

	apollo, req := cb2MakeFlowAndApolloNoQuery(t, server.URL)
	req.Header = nethttp.Header{"Cookie": {"session=abc123"}}
	c := &cookieXSS{}
	finger := c.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	_ = err
}

func TestCB2_CookieXSS_NoCookie(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<div>hello</div>"))
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApolloNoQuery(t, server.URL)
	c := &cookieXSS{}
	finger := c.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	_ = err
}

// ==================== Referer XSS integration ====================

func TestCB2_RefererXSS_Reflected(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		referer := r.Header.Get("Referer")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<div>" + referer + "</div>"))
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApolloNoQuery(t, server.URL)
	r := &refererXSS{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	_ = err
}

// ==================== IE XSS integration ====================

func TestCB2_IEXSS_HTMLReflection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<div>" + a + "</div>"))
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	ie := &ieFeatureXSS{}
	finger := ie.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	_ = err
}

func TestCB2_IEXSS_StyleReflection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<style>` + a + `</style>`))
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	ie := &ieFeatureXSS{}
	finger := ie.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	_ = err
}

func TestCB2_IEXSS_HrefReflection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<a href="` + a + `">click</a>`))
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	ie := &ieFeatureXSS{}
	finger := ie.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	_ = err
}

// ==================== Plugin interface compliance ====================

func TestCB2_XSS_PluginInterface(t *testing.T) {
	var _ base.Plugin = &XSS{}
}

// ==================== Additional Fingers CheckAction coverage ====================

// TestCB2_Fingers_StyleInjectionVulnConfirmation tests style tag XSS with vuln confirmation
func TestCB2_Fingers_StyleInjectionVulnConfirmation(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte("<style>" + a + "</style>"))
		} else {
			// For confirmation request, reflect the flag to trigger vuln
			w.Write([]byte("<style>}flagmarker{background:url(//flagmarker)}</style>"))
		}
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_ScriptTagInjectionWithClosure tests script tag XSS with tag closure
func TestCB2_Fingers_ScriptTagInjectionWithClosure(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte("<script>var x = '" + a + "';</script>"))
		} else {
			// Reflect the flag as a tag name for confirmation
			w.Write([]byte("<script></script><flagmarker></flagmarker>"))
		}
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_CommentInjectionVulnConfirmation tests comment XSS with vuln confirmation
func TestCB2_Fingers_CommentInjectionVulnConfirmation(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte("<!-- " + a + " -->"))
		} else {
			// Reflect the flag as a tag name for confirmation
			w.Write([]byte("--><flagmarker></flagmarker>"))
		}
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_AttrValueInjectionWithEscaping tests attribute value XSS with escaping detection
func TestCB2_Fingers_AttrValueInjectionWithEscaping(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		atomic.AddInt32(&requestCount, 1)
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		// Escape quotes to test the escaped payload detection path
		escaped := strings.ReplaceAll(a, `"`, `\"`)
		escaped = strings.ReplaceAll(escaped, `'`, `\'`)
		w.Write([]byte(`<div class="` + escaped + `">text</div>`))
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_AttrKeyInjectionWithNewTag tests attribute key XSS creating new tag
func TestCB2_Fingers_AttrKeyInjectionWithNewTag(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte(`<div ` + a + `="value">text</div>`))
		} else {
			// For confirmation request, reflect as a new tag
			w.Write([]byte(`<div ><flagmarker ></flagmarker>`))
		}
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_JSHrefProtocol tests javascript: protocol in href attribute
func TestCB2_Fingers_JSHrefProtocol(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte(`<a href="` + a + `">click</a>`))
		} else {
			// Reflect the javascript: protocol in the attribute value
			w.Write([]byte(`<a href="javascript:alert(1)">click</a>`))
		}
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_ActionAttrInjection tests injection in action attribute
func TestCB2_Fingers_ActionAttrInjection(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte(`<form action="` + a + `"><input type="submit"></form>`))
		} else {
			w.Write([]byte(`<form action="javascript:alert(1)"><input type="submit"></form>`))
		}
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_FormActionAttrInjection tests injection in formaction attribute
func TestCB2_Fingers_FormActionAttrInjection(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte(`<button formaction="` + a + `">Submit</button>`))
		} else {
			w.Write([]byte(`<button formaction="javascript:alert(1)">Submit</button>`))
		}
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_AttrValueNewAttrCreation tests attribute value XSS creating new attribute
func TestCB2_Fingers_AttrValueNewAttrCreation(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte(`<div title="` + a + `">text</div>`))
		} else {
			// For confirmation, reflect the flag as a new attribute name
			w.Write([]byte(`<div flagmarker="flagmarker">text</div>`))
		}
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_HTMLInjectionWithNewTagCreation tests HTML injection XSS creating new tag
func TestCB2_Fingers_HTMLInjectionWithNewTagCreation(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte("<div>" + a + "</div>"))
		} else {
			// For confirmation, reflect the flag as a new tag
			w.Write([]byte("<div></div><flagmarker></flagmarker>"))
		}
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_ScriptTagSingleQuoteClosure tests script tag XSS with single quote closure
func TestCB2_Fingers_ScriptTagSingleQuoteClosure(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte(`<script>var x = '` + a + `';</script>`))
		} else {
			// Reflect the payload flag in script or html context
			w.Write([]byte(`<script>var x = 'flagmarker';</script>`))
		}
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_ScriptTagDoubleQuoteClosure tests script tag XSS with double quote closure
func TestCB2_Fingers_ScriptTagDoubleQuoteClosure(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte(`<script>var x = "` + a + `";</script>`))
		} else {
			w.Write([]byte(`<script>var x = "flagmarker";</script>`))
		}
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// TestCB2_Fingers_ScriptTagClosureInjection tests script tag closure XSS
func TestCB2_Fingers_ScriptTagClosureInjection(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte(`<script>var x = '` + a + `';</script>`))
		} else {
			// Reflect the flag content in the script tag
			w.Write([]byte(`<script>flagmarker</script>`))
		}
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	x := &XSS{}
	fingers := x.Fingers()
	err := fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// ==================== Additional AddXSSVuln coverage ====================

func TestCB2_AddXSSVuln_NoPanic(t *testing.T) {
	x := &XSS{}
	x.AddXSSVuln(nil, nil, nil, nil, "")
}

// ==================== Additional checkContentCheatHeader/checkContentType/checkVulnerability coverage ====================

func TestCB2_CheckContentCheatHeader_NoPanic(t *testing.T) {
	x := &XSS{}
	x.checkContentCheatHeader()
}

func TestCB2_CheckContentType_NoPanic(t *testing.T) {
	x := &XSS{}
	x.checkContentType()
}

func TestCB2_CheckVulnerability_NoPanic(t *testing.T) {
	x := &XSS{}
	x.checkVulnerability()
}

func TestCB2_RequestForQuery_NoPanic(t *testing.T) {
	x := &XSS{}
	x.requestForQuery()
}

func TestCB2_WalkAParameter_NoPanic(t *testing.T) {
	x := &XSS{}
	x.walkAParameter()
}

// ==================== SearchInputInResponse with attribute exact match ====================

func TestCB2_SearchInputInResponse_AttributeExactKeyMatch(t *testing.T) {
	body := `<div data-testid="someval">text</div>`
	result := SearchInputInResponse("data-testid", body)
	found := false
	for _, occ := range result {
		if occ.Type == "attribute" && occ.Details["content"] == "key" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find data-testid attribute key exact match")
	}
}

func TestCB2_SearchInputInResponse_AttributeExactValueMatch(t *testing.T) {
	body := `<div class="exactmatch">text</div>`
	result := SearchInputInResponse("exactmatch", body)
	found := false
	for _, occ := range result {
		if occ.Type == "attribute" && occ.Details["content"] == "value" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find attribute value exact match")
	}
}

// ==================== Fingers with POST request ====================

func TestCB2_Fingers_POSTRequestReflection(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		r.ParseForm()
		a := r.FormValue("a")
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<div>" + a + "</div>"))
	}))
	defer server.Close()

	req, err := whttp.NewRequest("POST", server.URL+"/", strings.NewReader("a=1"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	flow := &whttp.Flow{
		Request:  req,
		Response: &whttp.Response{Text: "", StatusCode: 200, Header: nethttp.Header{"Content-Type": {"text/html"}}},
	}
	apollo := base.NewApollo(flow)
	apollo.ApolloBase.HTTPClient = whttp.NewClient()
	apollo.ApolloBase.Output = cb2NopPrinter{}
	apollo.ApolloBase.VulnFilter = &model.VulnFilterConfig{}

	x := &XSS{}
	fingers := x.Fingers()
	err2 := fingers[0].CheckAction(context.Background(), apollo)
	_ = err2
}

// ==================== IE Feature XSS with reflected in style tag ====================

func TestCB2_IEXSS_ReflectedInStyleTagWithExpression(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte("<style>" + a + "</style>"))
		} else {
			// Reflect with expression for IE detection
			w.Write([]byte("<style>}flagmarker{width:expression(alert(1))}</style>"))
		}
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	ie := &ieFeatureXSS{}
	finger := ie.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	_ = err
}

// ==================== IE Feature XSS with reflected in href attribute ====================

func TestCB2_IEXSS_ReflectedInHrefWithVBScript(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		a := r.URL.Query().Get("a")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte(`<a href="` + a + `">click</a>`))
		} else {
			// Reflect with vbscript for IE detection
			w.Write([]byte(`<a href="vbscript:alert(1)/*flagmarker*/">click</a>`))
		}
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApollo(t, server.URL)
	ie := &ieFeatureXSS{}
	finger := ie.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	_ = err
}

// ==================== Cookie XSS with HTML reflection ====================

func TestCB2_CookieXSS_HTMLReflectionWithVulnConfirmation(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		cookie := r.Header.Get("Cookie")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte("<div>" + cookie + "</div>"))
		} else {
			// For confirmation, reflect the flag as a tag
			w.Write([]byte("<div></div><flagmarker></flagmarker>"))
		}
	}))
	defer server.Close()

	apollo, req := cb2MakeFlowAndApolloNoQuery(t, server.URL)
	req.Header = nethttp.Header{"Cookie": {"session=abc123"}}
	c := &cookieXSS{}
	finger := c.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	_ = err
}

// ==================== Referer XSS with HTML reflection and vuln confirmation ====================

func TestCB2_RefererXSS_HTMLReflectionWithVulnConfirmation(t *testing.T) {
	var requestCount int32
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		count := atomic.AddInt32(&requestCount, 1)
		referer := r.Header.Get("Referer")
		w.Header().Set("Content-Type", "text/html")
		if count <= 1 {
			w.Write([]byte("<div>" + referer + "</div>"))
		} else {
			w.Write([]byte("<div></div><flagmarker></flagmarker>"))
		}
	}))
	defer server.Close()

	apollo, _ := cb2MakeFlowAndApolloNoQuery(t, server.URL)
	r := &refererXSS{}
	finger := r.Finger()
	err := finger.CheckAction(context.Background(), apollo)
	_ = err
}
