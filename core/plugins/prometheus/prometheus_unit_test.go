package prometheus

import (
	"net/url"
	"testing"
	"time"

	"wscan/core/model"
	"wscan/core/plugins/base"
)

func TestPrometheusDefaultConfig(t *testing.T) {
	p := &Prometheus{}
	cfg := p.DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
	}

	bc := cfg.BaseConfig()
	if bc.Name != "prometheus" {
		t.Errorf("Expected Name='prometheus', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("Expected Enabled=true")
	}

	pCfg, ok := cfg.(*Config)
	if !ok {
		t.Fatal("DefaultConfig() did not return *Config")
	}
	if pCfg.Depth != 1 {
		t.Errorf("Expected Depth=1, got %d", pCfg.Depth)
	}
}

func TestPrometheusClose(t *testing.T) {
	p := &Prometheus{}
	if err := p.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestPrometheusConfigBaseConfig(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "prometheus",
			Enabled: true,
		},
		Depth:       2,
		AutoLoadPOC: true,
	}
	bc := cfg.BaseConfig()
	if bc.Name != "prometheus" {
		t.Errorf("Expected Name='prometheus', got '%s'", bc.Name)
	}
	if !bc.Enabled {
		t.Error("Expected Enabled=true")
	}
}

func TestPrometheusConfigFields(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "prometheus",
			Enabled: true,
		},
		Depth:       3,
		POC:         []string{"poc1", "poc2"},
		Exclusive:   false,
		AutoLoadPOC: true,
		IncludePOC:  []string{"*weblogic*"},
		ExcludePOC:  []string{"*thinkphp*"},
	}
	if cfg.Depth != 3 {
		t.Errorf("Expected Depth=3, got %d", cfg.Depth)
	}
	if len(cfg.POC) != 2 {
		t.Errorf("Expected 2 POCs, got %d", len(cfg.POC))
	}
	if cfg.Exclusive {
		t.Error("Expected Exclusive=false")
	}
	if !cfg.AutoLoadPOC {
		t.Error("Expected AutoLoadPOC=true")
	}
	if len(cfg.IncludePOC) != 1 {
		t.Errorf("Expected 1 IncludePOC, got %d", len(cfg.IncludePOC))
	}
	if len(cfg.ExcludePOC) != 1 {
		t.Errorf("Expected 1 ExcludePOC, got %d", len(cfg.ExcludePOC))
	}
}

func TestPocPool(t *testing.T) {
	poc := PocPool.Get().(*Poc)
	if poc == nil {
		t.Error("PocPool.Get() returned nil")
	}
	PocPool.Put(poc)
}

func TestRuleStruct(t *testing.T) {
	r := Rule{
		Request: RuleRequest{
			Method:  "GET",
			Path:    "/test",
			Headers: map[string]string{"Content-Type": "application/json"},
			Body:    "",
		},
		Expression: "response.status == 200",
	}
	if r.Request.Method != "GET" {
		t.Errorf("Expected Method='GET', got '%s'", r.Request.Method)
	}
	if r.Request.Path != "/test" {
		t.Errorf("Expected Path='/test', got '%s'", r.Request.Path)
	}
	if r.Expression != "response.status == 200" {
		t.Errorf("Expected Expression='response.status == 200', got '%s'", r.Expression)
	}
}

func TestRuleRequestStruct(t *testing.T) {
	rr := RuleRequest{
		Cache:           true,
		Method:          "POST",
		Path:            "/api/data",
		Headers:         map[string]string{"Authorization": "Bearer token"},
		Body:            `{"key":"value"}`,
		FollowRedirects: true,
		Content:         "json",
		ReadTimeout:     "5s",
		ConnectionID:    "conn1",
	}
	if rr.Method != "POST" {
		t.Errorf("Expected Method='POST', got '%s'", rr.Method)
	}
	if !rr.Cache {
		t.Error("Expected Cache=true")
	}
	if !rr.FollowRedirects {
		t.Error("Expected FollowRedirects=true")
	}
}

func TestPocStruct(t *testing.T) {
	poc := Poc{
		Name:       "test-poc",
		Manual:     false,
		Transport:  "http",
		Expression: "rule1 && rule2",
	}
	if poc.Name != "test-poc" {
		t.Errorf("Expected Name='test-poc', got '%s'", poc.Name)
	}
	if poc.Transport != "http" {
		t.Errorf("Expected Transport='http', got '%s'", poc.Transport)
	}
}

func TestDetailStruct(t *testing.T) {
	d := Detail{
		Author:      "testauthor",
		Links:       []string{"http://example.com"},
		Description: "Test vulnerability",
		Version:     "1.0",
		Tags:        "rce,sqli",
	}
	if d.Author != "testauthor" {
		t.Errorf("Expected Author='testauthor', got '%s'", d.Author)
	}
	if len(d.Links) != 1 {
		t.Errorf("Expected 1 link, got %d", len(d.Links))
	}
	if d.Description != "Test vulnerability" {
		t.Errorf("Expected Description='Test vulnerability', got '%s'", d.Description)
	}
}

func TestFingerprintStructInPrometheus(t *testing.T) {
	fp := Fingerprint{
		Infos: []*Info{
			{Type: "web", ID: "nginx", Name: "Nginx", Version: "1.18", Confidence: 90},
		},
		HostInfo: &HostInfo{Hostname: "example.com"},
	}
	if len(fp.Infos) != 1 {
		t.Errorf("Expected 1 info, got %d", len(fp.Infos))
	}
	if fp.Infos[0].Name != "Nginx" {
		t.Errorf("Expected Info.Name='Nginx', got '%s'", fp.Infos[0].Name)
	}
	if fp.HostInfo.Hostname != "example.com" {
		t.Errorf("Expected Hostname='example.com', got '%s'", fp.HostInfo.Hostname)
	}
}

func TestInfoStruct(t *testing.T) {
	info := Info{
		Type:       "web",
		ID:         "apache",
		Name:       "Apache",
		Version:    "2.4",
		Confidence: 80,
	}
	if info.Type != "web" {
		t.Errorf("Expected Type='web', got '%s'", info.Type)
	}
	if info.Confidence != 80 {
		t.Errorf("Expected Confidence=80, got %d", info.Confidence)
	}
}

func TestVulnerabilityStruct(t *testing.T) {
	v := Vulnerability{
		ID:    "CVE-2021-1234",
		Match: "pattern",
	}
	if v.ID != "CVE-2021-1234" {
		t.Errorf("Expected ID='CVE-2021-1234', got '%s'", v.ID)
	}
}

func TestPayloadsStruct(t *testing.T) {
	p := Payloads{
		Continue: true,
	}
	if !p.Continue {
		t.Error("Expected Continue=true")
	}
}

func TestTaskStruct(t *testing.T) {
	task := Task{
		Poc:    Poc{Name: "test"},
		Target: "http://example.com",
	}
	if task.Poc.Name != "test" {
		t.Errorf("Expected Poc.Name='test', got '%s'", task.Poc.Name)
	}
	if task.Target != "http://example.com" {
		t.Errorf("Expected Target='http://example.com', got '%s'", task.Target)
	}
}

func TestHttpRequestCacheStruct(t *testing.T) {
	cache := HttpRequestCache{}
	if cache.Request != nil {
		t.Error("Expected nil Request in empty cache")
	}
}

func TestTCPUDPRequestCacheStruct(t *testing.T) {
	cache := TCPUDPRequestCache{}
	if cache.Response != nil {
		t.Error("Expected nil Response in empty cache")
	}
}

func TestYamlFormatStruct(t *testing.T) {
	yf := YamlFormat{
		ID:        "test-id",
		Name:      "test-name",
		Manual:    false,
		Transport: "http",
	}
	if yf.ID != "test-id" {
		t.Errorf("Expected ID='test-id', got '%s'", yf.ID)
	}
	if yf.Transport != "http" {
		t.Errorf("Expected Transport='http', got '%s'", yf.Transport)
	}
}

func TestIdentifyYamlPocType_InvalidPath(t *testing.T) {
	result := identifyYamlPocType("/nonexistent/path/to/file.yaml")
	if result != -1 {
		t.Errorf("Expected -1 for non-existent file, got %d", result)
	}
}

func TestIdentifyYamlPocType_InvalidAbsPath(t *testing.T) {
	result := identifyYamlPocType("")
	if result != -1 {
		t.Errorf("Expected -1 for empty path, got %d", result)
	}
}

func TestPocTypeConstants(t *testing.T) {
	if PocTypeXray != 0 {
		t.Errorf("Expected PocTypeXray=0, got %d", PocTypeXray)
	}
	if PocTypeNuclei != 1 {
		t.Errorf("Expected PocTypeNuclei=1, got %d", PocTypeNuclei)
	}
}

func TestNucleiFingerDump(t *testing.T) {
	nf := NucleiFinger{}
	data, err := nf.Dump()
	if data != nil {
		t.Errorf("Expected nil data from Dump(), got %v", data)
	}
	if err != nil {
		t.Errorf("Expected nil error from Dump(), got %v", err)
	}
}

func TestNucleiFingerInit(t *testing.T) {
	nf := NucleiFinger{}
	err := nf.Init(true)
	if err != nil {
		t.Errorf("Expected nil error from Init(), got %v", err)
	}
}

func TestNucleiFingerMarshalYAML(t *testing.T) {
	nf := NucleiFinger{}
	data, err := nf.MarshalYAML()
	if data != nil {
		t.Errorf("Expected nil data from MarshalYAML(), got %v", data)
	}
	if err != nil {
		t.Errorf("Expected nil error from MarshalYAML(), got %v", err)
	}
}

func TestYamlFingerDump(t *testing.T) {
	yf := YamlFinger{}
	data, err := yf.Dump()
	if data != nil {
		t.Errorf("Expected nil data from Dump(), got %v", data)
	}
	if err != nil {
		t.Errorf("Expected nil error from Dump(), got %v", err)
	}
}

func TestYamlFingerInit(t *testing.T) {
	yf := YamlFinger{}
	err := yf.Init(true)
	if err != nil {
		t.Errorf("Expected nil error from Init(), got %v", err)
	}
}

func TestYamlFingerMarshalYAML(t *testing.T) {
	yf := YamlFinger{}
	data, err := yf.MarshalYAML()
	if data != nil {
		t.Errorf("Expected nil data from MarshalYAML(), got %v", data)
	}
	if err != nil {
		t.Errorf("Expected nil error from MarshalYAML(), got %v", err)
	}
}

func TestYamlScriptMarshalYAML(t *testing.T) {
	ys := YamlScript{}
	data, err := ys.MarshalYAML()
	if data != nil {
		t.Errorf("Expected nil data from MarshalYAML(), got %v", data)
	}
	if err != nil {
		t.Errorf("Expected nil error from MarshalYAML(), got %v", err)
	}
}

func TestYamlFingerDumpFromPoc(t *testing.T) {
	poc := &Poc{
		Name:       "test-poc",
		Transport:  "http",
		Expression: "true",
	}
	yf := YamlFingerDump(poc)
	if yf == nil {
		t.Fatal("YamlFingerDump() returned nil")
	}
	if yf.poc == nil {
		t.Error("Expected non-nil poc in YamlFinger")
	}
	if yf.poc.Name != "test-poc" {
		t.Errorf("Expected poc.Name='test-poc', got '%s'", yf.poc.Name)
	}
}

func TestRuleMapSliceCreation(t *testing.T) {
	ORDER = 0
	slice := make(RuleMapSlice, 0)
	if len(slice) != 0 {
		t.Errorf("Expected empty RuleMapSlice, got %d items", len(slice))
	}
}

func TestMockOutputWriterCreation(t *testing.T) {
	mow := NewMockOutputWriter(false)
	if mow == nil {
		t.Fatal("NewMockOutputWriter() returned nil")
	}
	mow.Close()
}

func TestMockOutputWriter_Colorizer(t *testing.T) {
	mow := NewMockOutputWriter(false)
	a := mow.Colorizer()
	if a == nil {
		t.Error("Expected non-nil Colorizer")
	}
}

func TestMockOutputWriter_ResultCount(t *testing.T) {
	mow := NewMockOutputWriter(false)
	count := mow.ResultCount()
	if count != 0 {
		t.Errorf("Expected ResultCount=0, got %d", count)
	}
}

func TestMockProgressClient(t *testing.T) {
	mpc := &MockProgressClient{}
	mpc.Stop()
	mpc.Init(0, 0, 0)
	mpc.AddToTotal(0)
	mpc.IncrementRequests()
	mpc.SetRequests(0)
	mpc.IncrementMatched()
	mpc.IncrementErrorsBy(0)
	mpc.IncrementFailedRequestsBy(0)
}

func TestNoopWriter(t *testing.T) {
	nw := &NoopWriter{}
	nw.Write([]byte("test"), 0)
}

func TestParseUrlFunc(t *testing.T) {
	u, err := url.Parse("http://example.com:8080/path?query=1#fragment")
	if err != nil {
		t.Fatalf("Failed to parse URL: %v", err)
	}
	urlType := ParseUrl(u)
	if urlType == nil {
		t.Fatal("ParseUrl() returned nil")
	}
	if urlType.Scheme != "http" {
		t.Errorf("Expected Scheme='http', got '%s'", urlType.Scheme)
	}
	if urlType.Domain != "example.com" {
		t.Errorf("Expected Domain='example.com', got '%s'", urlType.Domain)
	}
	if urlType.Port != "8080" {
		t.Errorf("Expected Port='8080', got '%s'", urlType.Port)
	}
	if urlType.Path != "/path" {
		t.Errorf("Expected Path='/path', got '%s'", urlType.Path)
	}
	if urlType.Query != "query=1" {
		t.Errorf("Expected Query='query=1', got '%s'", urlType.Query)
	}
	if urlType.Fragment != "fragment" {
		t.Errorf("Expected Fragment='fragment', got '%s'", urlType.Fragment)
	}
	PutUrlType(urlType)
}

func TestParseUrl_NoPort(t *testing.T) {
	u, _ := url.Parse("http://example.com/path")
	urlType := ParseUrl(u)
	if urlType.Port != "" {
		t.Errorf("Expected empty Port, got '%s'", urlType.Port)
	}
	PutUrlType(urlType)
}

func TestPutUrlType(t *testing.T) {
	u, _ := url.Parse("http://example.com:8080/path")
	urlType := ParseUrl(u)
	PutUrlType(urlType)
	if urlType.Scheme != "" {
		t.Errorf("Expected empty Scheme after PutUrlType, got '%s'", urlType.Scheme)
	}
}

func TestPutRequest(t *testing.T) {
	req := &model.Request{
		Method:      "GET",
		ContentType: "text/html",
	}
	PutRequest(req)
	if req.Method != "" {
		t.Error("Expected Method to be cleared after PutRequest")
	}
	if req.ContentType != "" {
		t.Error("Expected ContentType to be cleared after PutRequest")
	}
}

func TestPutResponse(t *testing.T) {
	resp := &model.Response{
		Status:      200,
		ContentType: "text/html",
	}
	PutResponse(resp)
	if resp.Status != 0 {
		t.Error("Expected Status to be cleared after PutResponse")
	}
	if resp.ContentType != "" {
		t.Error("Expected ContentType to be cleared after PutResponse")
	}
}

func TestPutAddrType(t *testing.T) {
	addrType := &model.AddrType{
		Transport: "tcp",
		Addr:      "127.0.0.1:8080",
	}
	PutAddrType(addrType)
	if addrType.Transport != "" {
		t.Error("Expected Transport to be cleared after PutAddrType")
	}
}

func TestPutConnectInfo(t *testing.T) {
	connInfo := &model.ConnInfoType{
		Source:      &model.AddrType{},
		Destination: &model.AddrType{},
	}
	PutConnectInfo(connInfo)
	if connInfo.Source != nil {
		t.Error("Expected Source to be nil after PutConnectInfo")
	}
	if connInfo.Destination != nil {
		t.Error("Expected Destination to be nil after PutConnectInfo")
	}
}

func TestParseTCPUDPRequest(t *testing.T) {
	content := []byte("test data")
	req, err := ParseTCPUDPRequest(content)
	if err != nil {
		t.Errorf("ParseTCPUDPRequest() returned error: %v", err)
	}
	if req == nil {
		t.Fatal("ParseTCPUDPRequest() returned nil")
	}
	if string(req.Raw) != "test data" {
		t.Errorf("Expected Raw='test data', got '%s'", string(req.Raw))
	}
}

func TestInitHttpClient(t *testing.T) {
	err := InitHttpClient(10, "", 10*time.Second)
	if err != nil {
		t.Errorf("InitHttpClient() returned error: %v", err)
	}
	if Client == nil {
		t.Error("Expected non-nil Client after InitHttpClient")
	}
	if ClientNoRedirect == nil {
		t.Error("Expected non-nil ClientNoRedirect after InitHttpClient")
	}
}

func TestInitHttpClient_WithProxy(t *testing.T) {
	err := InitHttpClient(10, "http://127.0.0.1:9999", 10*time.Second)
	if err != nil {
		t.Errorf("InitHttpClient() with proxy returned error: %v", err)
	}
}

func TestInitHttpClient_InvalidProxy(t *testing.T) {
	err := InitHttpClient(10, "://invalid-proxy", 10*time.Second)
	if err == nil {
		t.Error("Expected error for invalid proxy URL")
	}
}

func TestMockOutputWriter_Write(t *testing.T) {
	mow := NewMockOutputWriter(false)
	// Write without callback should not panic
	err := mow.Write(nil)
	if err != nil {
		t.Errorf("Write() returned error: %v", err)
	}
}

func TestMockOutputWriter_Request(t *testing.T) {
	mow := NewMockOutputWriter(false)
	// Request without callback should not panic
	mow.Request("template-id", "http://example.com", "http", nil)
}

func TestMockOutputWriter_RequestStatsLog(t *testing.T) {
	mow := NewMockOutputWriter(false)
	mow.RequestStatsLog("200", "ok")
}

func TestMockOutputWriter_WriteStoreDebugData(t *testing.T) {
	mow := NewMockOutputWriter(false)
	mow.WriteStoreDebugData("host", "templateID", "eventType", "data")
}
