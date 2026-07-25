package path_traversal

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

// ==================== PathTraversal Init with URLChecker ====================

func TestBoostPathTraversal_Init(t *testing.T) {
	p := &PathTraversal{}
	cfg := p.DefaultConfig()
	ab := &base.ApolloBase{
		FilterConfig:    &checker.RequestCheckerConfig{},
		FilterContainer: filter.NewSyncMapFilter(),
	}
	err := p.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init returned error: %v", err)
	}
}

// ==================== isValueReplacePayload tests ====================

func TestBoostIsValueReplacePayload(t *testing.T) {
	tests := []struct {
		vector   string
		expected bool
	}{
		{"php://filter/convert.base64-encode/resource=index.php", true},
		{"file:///etc/passwd", true},
		{"file://localhost/etc/passwd", true},
		{"../../etc/passwd", false},
		{"/etc/passwd", false},
		{"http://example.com/shell.php", false},
	}

	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			result := isValueReplacePayload(tt.vector)
			if result != tt.expected {
				t.Errorf("isValueReplacePayload(%q) = %v, want %v", tt.vector, result, tt.expected)
			}
		})
	}
}

// ==================== pathTraversalRules loaded ====================

func TestBoostPathTraversalRulesLoaded(t *testing.T) {
	if len(pathTraversalRules) == 0 {
		t.Error("expected pathTraversalRules to be loaded by init()")
	}
	// Check that rules have compiled regexps
	for i, rule := range pathTraversalRules {
		if rule.compiled == nil {
			t.Errorf("rule[%d] has nil compiled regexp", i)
		}
		if rule.typ == "" {
			t.Errorf("rule[%d] has empty typ", i)
		}
	}
}

// ==================== execAction with test servers ====================

type nopPTPrinter struct{}

func (nopPTPrinter) AddInterceptor(func(any) (any, error)) printer.Printer { return nopPTPrinter{} }
func (nopPTPrinter) Close() error                                          { return nil }
func (nopPTPrinter) Print(any) error                                       { return nil }

func TestBoostPathTraversal_ExecAction_SafeServer(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Safe page</body></html>"))
	}))
	defer server.Close()

	req, err := whttp.NewRequest("GET", server.URL+"/?file=test.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	flow := &whttp.Flow{
		Request:  req,
		Response: &whttp.Response{Text: "", StatusCode: 200, Header: nethttp.Header{"Content-Type": {"text/html"}}},
	}

	apollo := base.NewApollo(flow)
	apollo.ApolloBase.HTTPClient = whttp.NewClient()
	apollo.ApolloBase.Output = nopPTPrinter{}
	apollo.ApolloBase.VulnFilter = &model.VulnFilterConfig{}

	p := &PathTraversal{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()

	err = fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

func TestBoostPathTraversal_ExecAction_ServerError(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	req, err := whttp.NewRequest("GET", server.URL+"/?page=about", nil)
	if err != nil {
		t.Fatal(err)
	}
	flow := &whttp.Flow{
		Request:  req,
		Response: &whttp.Response{Text: "", StatusCode: 200, Header: nethttp.Header{"Content-Type": {"text/html"}}},
	}

	apollo := base.NewApollo(flow)
	apollo.ApolloBase.HTTPClient = whttp.NewClient()
	apollo.ApolloBase.Output = nopPTPrinter{}
	apollo.ApolloBase.VulnFilter = &model.VulnFilterConfig{}

	p := &PathTraversal{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()

	err = fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

func TestBoostPathTraversal_ExecAction_NoParams(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>No params</body></html>"))
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
	apollo.ApolloBase.Output = nopPTPrinter{}
	apollo.ApolloBase.VulnFilter = &model.VulnFilterConfig{}

	p := &PathTraversal{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()

	err = fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}

// ==================== Rule struct coverage ====================

func TestBoostRule_StructFields(t *testing.T) {
	r := Rule{
		Vector:  "../../etc/passwd",
		Windows: 5,
		Linux:   5,
	}
	if r.Vector != "../../etc/passwd" {
		t.Error("Unexpected Vector")
	}
	if r.Windows != 5 {
		t.Error("Unexpected Windows")
	}
	if r.Linux != 5 {
		t.Error("Unexpected Linux")
	}
}

// ==================== Root struct coverage ====================

func TestBoostRoot_StructFields(t *testing.T) {
	r := Root{}
	if len(r.LFI) != 0 {
		t.Error("Expected empty LFI")
	}
	if len(r.RFI) != 0 {
		t.Error("Expected empty RFI")
	}
	if len(r.FI) != 0 {
		t.Error("Expected empty FI")
	}
}

// ==================== PathTraversal plugin interface ====================

func TestBoostPathTraversal_PluginInterface(t *testing.T) {
	var _ base.Plugin = &PathTraversal{}
}

// ==================== Config BaseConfig ====================

func TestBoostConfig_BaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "path_traversal", Enabled: true},
	}
	bc := cfg.BaseConfig()
	if bc.Name != "path_traversal" {
		t.Errorf("expected Name 'path_traversal', got '%s'", bc.Name)
	}
}

// ==================== GetConfig before and after Init ====================

func TestBoostPathTraversal_GetConfig_BeforeInit(t *testing.T) {
	p := &PathTraversal{}
	cfg := p.GetConfig()
	if cfg != nil {
		t.Error("expected nil config before Init")
	}
}

func TestBoostPathTraversal_GetConfig_AfterInit(t *testing.T) {
	p := &PathTraversal{}
	cfg := p.DefaultConfig()
	p.PluginMixinInitConfig.Config = cfg
	gotCfg := p.GetConfig()
	if gotCfg == nil {
		t.Fatal("expected non-nil config after setting")
	}
}

// ==================== execAction with POST parameters ====================

func TestBoostPathTraversal_ExecAction_PostParams(t *testing.T) {
	server := httptest.NewServer(nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Response</body></html>"))
	}))
	defer server.Close()

	req, err := whttp.NewRequest("POST", server.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	flow := &whttp.Flow{
		Request:  req,
		Response: &whttp.Response{Text: "", StatusCode: 200, Header: nethttp.Header{"Content-Type": {"text/html"}}},
	}

	apollo := base.NewApollo(flow)
	apollo.ApolloBase.HTTPClient = whttp.NewClient()
	apollo.ApolloBase.Output = nopPTPrinter{}
	apollo.ApolloBase.VulnFilter = &model.VulnFilterConfig{}

	p := &PathTraversal{}
	p.PluginMixinInitConfig.Config = p.DefaultConfig()
	fingers := p.Fingers()

	err = fingers[0].CheckAction(context.Background(), apollo)
	_ = err
}
