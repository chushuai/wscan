package prometheus

import (
	"testing"
	"time"

	nucleimodel "github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	nucleitypes "github.com/projectdiscovery/nuclei/v3/pkg/types"
	"gopkg.in/yaml.v2"
)

// ==================== testutils.go coverage ====================

// TestCB2_NewMockOutputWriter_OmitTrue tests creation with omitTemplate=true
func TestCB2_NewMockOutputWriter_OmitTrue(t *testing.T) {
	mow := NewMockOutputWriter(true)
	if mow == nil {
		t.Fatal("NewMockOutputWriter(true) returned nil")
	}
	if !mow.omitTemplate {
		t.Error("Expected omitTemplate=true")
	}
}

// TestCB2_NewMockOutputWriter_OmitFalse tests creation with omitTemplate=false
func TestCB2_NewMockOutputWriter_OmitFalse(t *testing.T) {
	mow := NewMockOutputWriter(false)
	if mow == nil {
		t.Fatal("NewMockOutputWriter(false) returned nil")
	}
	if mow.omitTemplate {
		t.Error("Expected omitTemplate=false")
	}
}

// TestCB2_MockOutputWriter_Write_WithCallback tests Write with callback set
func TestCB2_MockOutputWriter_Write_WithCallback(t *testing.T) {
	mow := NewMockOutputWriter(false)
	called := false
	mow.WriteCallback = func(o *output.ResultEvent) {
		called = true
	}
	err := mow.Write(&output.ResultEvent{TemplateID: "test-template"})
	if err != nil {
		t.Errorf("Write() returned error: %v", err)
	}
	if !called {
		t.Error("WriteCallback was not called")
	}
}

// TestCB2_MockOutputWriter_Write_NilResult tests Write with nil result
func TestCB2_MockOutputWriter_Write_NilResult(t *testing.T) {
	mow := NewMockOutputWriter(false)
	err := mow.Write(nil)
	if err != nil {
		t.Errorf("Write(nil) returned error: %v", err)
	}
}

// TestCB2_MockOutputWriter_Request_WithCallback tests Request with callback
func TestCB2_MockOutputWriter_Request_WithCallback(t *testing.T) {
	mow := NewMockOutputWriter(false)
	var gotTemplateID, gotURL, gotRequestType string
	mow.RequestCallback = func(templateID, url, requestType string, err error) {
		gotTemplateID = templateID
		gotURL = url
		gotRequestType = requestType
	}
	mow.Request("tpl-1", "http://example.com", "http", nil)
	if gotTemplateID != "tpl-1" {
		t.Errorf("Expected templateID='tpl-1', got '%s'", gotTemplateID)
	}
	if gotURL != "http://example.com" {
		t.Errorf("Expected url='http://example.com', got '%s'", gotURL)
	}
	if gotRequestType != "http" {
		t.Errorf("Expected requestType='http', got '%s'", gotRequestType)
	}
}

// TestCB2_MockOutputWriter_WriteFailure_WithResults tests WriteFailure with existing results
func TestCB2_MockOutputWriter_WriteFailure_WithResults(t *testing.T) {
	mow := NewMockOutputWriter(false)
	var writtenResults []*output.ResultEvent
	mow.WriteCallback = func(o *output.ResultEvent) {
		writtenResults = append(writtenResults, o)
	}
	wrappedEvent := &output.InternalWrappedEvent{
		Results: []*output.ResultEvent{
			{TemplateID: "test-1", MatcherStatus: true},
			{TemplateID: "test-2", MatcherStatus: true},
		},
	}
	err := mow.WriteFailure(wrappedEvent)
	if err != nil {
		t.Errorf("WriteFailure() returned error: %v", err)
	}
	if len(writtenResults) != 2 {
		t.Fatalf("Expected 2 written results, got %d", len(writtenResults))
	}
	for i, r := range writtenResults {
		if r.MatcherStatus {
			t.Errorf("Result[%d]: Expected MatcherStatus=false", i)
		}
	}
}

// TestCB2_MockOutputWriter_WriteFailure_NoResults tests WriteFailure without existing results
func TestCB2_MockOutputWriter_WriteFailure_NoResults(t *testing.T) {
	mow := NewMockOutputWriter(false)
	var writtenResults []*output.ResultEvent
	mow.WriteCallback = func(o *output.ResultEvent) {
		writtenResults = append(writtenResults, o)
	}
	wrappedEvent := &output.InternalWrappedEvent{
		InternalEvent: map[string]interface{}{
			"template-id":       "test-template",
			"template-path":     "/path/to/template.yaml",
			"template-verifier": "",
			"type":              "http",
			"host":              "http://example.com",
			"request":           "GET / HTTP/1.1",
			"response":          "HTTP/1.1 200 OK",
			"error":             "",
		},
		Results: []*output.ResultEvent{},
	}
	err := mow.WriteFailure(wrappedEvent)
	if err != nil {
		t.Errorf("WriteFailure() returned error: %v", err)
	}
	if len(writtenResults) != 1 {
		t.Fatalf("Expected 1 written result, got %d", len(writtenResults))
	}
	if writtenResults[0].MatcherStatus {
		t.Error("Expected MatcherStatus=false")
	}
}

// TestCB2_MockOutputWriter_WriteFailure_WithTemplateInfo tests WriteFailure with template-info in event
func TestCB2_MockOutputWriter_WriteFailure_WithTemplateInfo(t *testing.T) {
	mow := NewMockOutputWriter(false)
	var writtenResults []*output.ResultEvent
	mow.WriteCallback = func(o *output.ResultEvent) {
		writtenResults = append(writtenResults, o)
	}
	wrappedEvent := &output.InternalWrappedEvent{
		InternalEvent: map[string]interface{}{
			"template-id":       "test-template",
			"template-path":     "/path/to/template.yaml",
			"template-verifier": "",
			"type":              "http",
			"host":              "http://example.com",
			"request":           "GET / HTTP/1.1",
			"response":          "HTTP/1.1 200 OK",
			"error":             "",
			"template-info":     nucleimodel.Info{Name: "test-info"},
		},
		Results: []*output.ResultEvent{},
	}
	err := mow.WriteFailure(wrappedEvent)
	if err != nil {
		t.Errorf("WriteFailure() returned error: %v", err)
	}
	if len(writtenResults) != 1 {
		t.Fatalf("Expected 1 written result, got %d", len(writtenResults))
	}
}

// TestCB2_MockOutputWriter_WriteFailure_WithIP tests WriteFailure with ip in event
func TestCB2_MockOutputWriter_WriteFailure_WithIP(t *testing.T) {
	mow := NewMockOutputWriter(false)
	var writtenResults []*output.ResultEvent
	mow.WriteCallback = func(o *output.ResultEvent) {
		writtenResults = append(writtenResults, o)
	}
	wrappedEvent := &output.InternalWrappedEvent{
		InternalEvent: map[string]interface{}{
			"template-id":       "test-template",
			"template-path":     "/path/to/template.yaml",
			"template-verifier": "",
			"type":              "http",
			"host":              "http://example.com",
			"ip":                "10.0.0.1",
			"path":              "/test",
			"request":           "GET / HTTP/1.1",
			"response":          "HTTP/1.1 200 OK",
			"error":             "",
		},
		Results: []*output.ResultEvent{},
	}
	err := mow.WriteFailure(wrappedEvent)
	if err != nil {
		t.Errorf("WriteFailure() returned error: %v", err)
	}
	if len(writtenResults) != 1 {
		t.Fatalf("Expected 1 written result, got %d", len(writtenResults))
	}
	if writtenResults[0].IP != "10.0.0.1" {
		t.Errorf("Expected IP='10.0.0.1', got '%s'", writtenResults[0].IP)
	}
}

// TestCB2_MockOutputWriter_encodeTemplate_NonExistentPath tests encodeTemplate with a path that doesn't exist
func TestCB2_MockOutputWriter_encodeTemplate_NonExistentPath(t *testing.T) {
	mow := NewMockOutputWriter(false)
	result := mow.encodeTemplate("/nonexistent/path/template.yaml")
	if result != "" {
		t.Errorf("Expected empty string for non-existent path, got '%s'", result)
	}
}

// TestCB2_MockOutputWriter_encodeTemplate_OmitTrue tests encodeTemplate with omitTemplate=true
func TestCB2_MockOutputWriter_encodeTemplate_OmitTrue(t *testing.T) {
	mow := NewMockOutputWriter(true)
	result := mow.encodeTemplate("/nonexistent/path/template.yaml")
	if result != "" {
		t.Errorf("Expected empty string when omitTemplate=true, got '%s'", result)
	}
}

// TestCB2_MockOutputWriter_Close tests Close method
func TestCB2_MockOutputWriter_Close(t *testing.T) {
	mow := NewMockOutputWriter(false)
	mow.Close()
}

// TestCB2_NoopWriter_Write tests NoopWriter.Write
func TestCB2_NoopWriter_Write(t *testing.T) {
	nw := &NoopWriter{}
	nw.Write([]byte("test"), 0)
}

// TestCB2_MockProgressClient_AllMethods tests all MockProgressClient methods
func TestCB2_MockProgressClient_AllMethods(t *testing.T) {
	mpc := &MockProgressClient{}
	mpc.Stop()
	mpc.Init(100, 10, 1000)
	mpc.AddToTotal(50)
	mpc.IncrementRequests()
	mpc.SetRequests(42)
	mpc.IncrementMatched()
	mpc.IncrementErrorsBy(5)
	mpc.IncrementFailedRequestsBy(3)
}

// TestCB2_NewMockExecuterOptions_NilInfo tests NewMockExecuterOptions with nil TemplateInfo
func TestCB2_NewMockExecuterOptions_NilInfo(t *testing.T) {
	opts := &nucleitypes.Options{
		RateLimit:         150,
		RateLimitDuration: time.Second,
	}
	execOpts := NewMockExecuterOptions(opts, nil)
	if execOpts == nil {
		t.Fatal("NewMockExecuterOptions() returned nil")
	}
	if execOpts.Options != opts {
		t.Error("Expected Options to be set")
	}
	if execOpts.Output == nil {
		t.Error("Expected non-nil Output")
	}
	if execOpts.Catalog == nil {
		t.Error("Expected non-nil Catalog")
	}
	if execOpts.RateLimiter == nil {
		t.Error("Expected non-nil RateLimiter")
	}
}

// TestCB2_NewMockExecuterOptions_WithInfo tests NewMockExecuterOptions with TemplateInfo
func TestCB2_NewMockExecuterOptions_WithInfo(t *testing.T) {
	opts := &nucleitypes.Options{
		RateLimit:         150,
		RateLimitDuration: time.Second,
	}
	info := &TemplateInfo{
		ID:   "test-id",
		Info: nucleimodel.Info{Name: "test", SeverityHolder: severity.Holder{Severity: severity.Low}},
		Path: "/path/to/template.yaml",
	}
	execOpts := NewMockExecuterOptions(opts, info)
	if execOpts == nil {
		t.Fatal("NewMockExecuterOptions() returned nil")
	}
	if execOpts.TemplateID != "test-id" {
		t.Errorf("Expected TemplateID='test-id', got '%s'", execOpts.TemplateID)
	}
	if execOpts.TemplatePath != "/path/to/template.yaml" {
		t.Errorf("Expected TemplatePath='/path/to/template.yaml', got '%s'", execOpts.TemplatePath)
	}
}

// TestCB2_DefaultOptions tests the DefaultOptions variable
func TestCB2_DefaultOptions(t *testing.T) {
	if DefaultOptions.RateLimit != 150 {
		t.Errorf("Expected RateLimit=150, got %d", DefaultOptions.RateLimit)
	}
	if DefaultOptions.Timeout != 5 {
		t.Errorf("Expected Timeout=5, got %d", DefaultOptions.Timeout)
	}
	if DefaultOptions.BulkSize != 25 {
		t.Errorf("Expected BulkSize=25, got %d", DefaultOptions.BulkSize)
	}
	if !DefaultOptions.NoColor {
		t.Error("Expected NoColor=true")
	}
}

// TestCB2_TemplateInfo tests the TemplateInfo struct
func TestCB2_TemplateInfo(t *testing.T) {
	info := TemplateInfo{
		ID:   "CVE-2021-1234",
		Info: nucleimodel.Info{Name: "Test Template"},
		Path: "/path/to/template.yaml",
	}
	if info.ID != "CVE-2021-1234" {
		t.Errorf("Expected ID='CVE-2021-1234', got '%s'", info.ID)
	}
	if info.Path != "/path/to/template.yaml" {
		t.Errorf("Expected Path='/path/to/template.yaml', got '%s'", info.Path)
	}
}

// ==================== yaml_finger.go coverage ====================

// TestCB2_YamlFinger_Dump tests YamlFinger.Dump
func TestCB2_YamlFinger_Dump(t *testing.T) {
	yf := YamlFinger{}
	data, err := yf.Dump()
	if data != nil {
		t.Errorf("Expected nil data from Dump(), got %v", data)
	}
	if err != nil {
		t.Errorf("Expected nil error from Dump(), got %v", err)
	}
}

// TestCB2_YamlFinger_Init tests YamlFinger.Init
func TestCB2_YamlFinger_Init(t *testing.T) {
	yf := YamlFinger{}
	err := yf.Init(true)
	if err != nil {
		t.Errorf("Expected nil error from Init(), got %v", err)
	}
}

// TestCB2_YamlFinger_MarshalYAML tests YamlFinger.MarshalYAML
func TestCB2_YamlFinger_MarshalYAML(t *testing.T) {
	yf := YamlFinger{}
	data, err := yf.MarshalYAML()
	if data != nil {
		t.Errorf("Expected nil data from MarshalYAML(), got %v", data)
	}
	if err != nil {
		t.Errorf("Expected nil error from MarshalYAML(), got %v", err)
	}
}

// TestCB2_YamlFinger_compileNode tests YamlFinger.compileNode
func TestCB2_YamlFinger_compileNode(t *testing.T) {
	yf := YamlFinger{}
	yf.compileNode()
}

// TestCB2_YamlFinger_compilePayloads tests YamlFinger.compilePayloads
func TestCB2_YamlFinger_compilePayloads(t *testing.T) {
	yf := YamlFinger{}
	yf.compilePayloads()
}

// TestCB2_YamlFinger_run tests YamlFinger.run
func TestCB2_YamlFinger_run(t *testing.T) {
	yf := YamlFinger{}
	yf.run()
}

// TestCB2_YamlFinger_Finger_NoReverse tests YamlFinger.Finger with no reverse in set
func TestCB2_YamlFinger_Finger_NoReverse(t *testing.T) {
	poc := &Poc{
		Name:       "test-poc-no-reverse",
		Transport:  "http",
		Expression: "true",
		Set: yaml.MapSlice{
			{Key: "var1", Value: "simple_value"},
		},
	}
	yf := &YamlFinger{poc: poc}
	f := yf.Finger()
	if f == nil {
		t.Fatal("Finger() returned nil")
	}
	if f.Channel != "web-directory" {
		t.Errorf("Expected Channel='web-directory', got '%s'", f.Channel)
	}
	if f.NeedReverse {
		t.Error("Expected NeedReverse=false when no newReverse in set")
	}
	if f.Binding == nil {
		t.Fatal("Expected non-nil Binding")
	}
	if f.Binding.ID != "test-poc-no-reverse" {
		t.Errorf("Expected Binding.ID='test-poc-no-reverse', got '%s'", f.Binding.ID)
	}
	if f.ExecAction == nil {
		t.Error("Expected non-nil ExecAction")
	}
}

// TestCB2_YamlFinger_Finger_WithReverse tests YamlFinger.Finger with newReverse in set
func TestCB2_YamlFinger_Finger_WithReverse(t *testing.T) {
	poc := &Poc{
		Name:       "test-poc-reverse",
		Transport:  "http",
		Expression: "true",
		Set: yaml.MapSlice{
			{Key: "reverse", Value: "newReverse()"},
		},
	}
	yf := &YamlFinger{poc: poc}
	f := yf.Finger()
	if f == nil {
		t.Fatal("Finger() returned nil")
	}
	if !f.NeedReverse {
		t.Error("Expected NeedReverse=true when newReverse is in set")
	}
}

// TestCB2_YamlFingerDump tests the YamlFingerDump function
func TestCB2_YamlFingerDump(t *testing.T) {
	poc := &Poc{
		Name:       "dump-test-poc",
		Transport:  "http",
		Expression: "rule1",
	}
	yf := YamlFingerDump(poc)
	if yf == nil {
		t.Fatal("YamlFingerDump() returned nil")
	}
	if yf.poc == nil {
		t.Error("Expected non-nil poc")
	}
	if yf.poc.Name != "dump-test-poc" {
		t.Errorf("Expected poc.Name='dump-test-poc', got '%s'", yf.poc.Name)
	}
}

// ==================== nuclei_finger.go coverage ====================

// TestCB2_NucleiFinger_Dump tests NucleiFinger.Dump
func TestCB2_NucleiFinger_Dump(t *testing.T) {
	nf := NucleiFinger{}
	data, err := nf.Dump()
	if data != nil {
		t.Errorf("Expected nil data from Dump(), got %v", data)
	}
	if err != nil {
		t.Errorf("Expected nil error from Dump(), got %v", err)
	}
}

// TestCB2_NucleiFinger_Init tests NucleiFinger.Init
func TestCB2_NucleiFinger_Init(t *testing.T) {
	nf := NucleiFinger{}
	err := nf.Init(true)
	if err != nil {
		t.Errorf("Expected nil error from Init(), got %v", err)
	}
}

// TestCB2_NucleiFinger_MarshalYAML tests NucleiFinger.MarshalYAML
func TestCB2_NucleiFinger_MarshalYAML(t *testing.T) {
	nf := NucleiFinger{}
	data, err := nf.MarshalYAML()
	if data != nil {
		t.Errorf("Expected nil data from MarshalYAML(), got %v", data)
	}
	if err != nil {
		t.Errorf("Expected nil error from MarshalYAML(), got %v", err)
	}
}

// TestCB2_NucleiFinger_compileNode tests NucleiFinger.compileNode
func TestCB2_NucleiFinger_compileNode(t *testing.T) {
	nf := NucleiFinger{}
	nf.compileNode()
}

// TestCB2_NucleiFinger_compilePayloads tests NucleiFinger.compilePayloads
func TestCB2_NucleiFinger_compilePayloads(t *testing.T) {
	nf := NucleiFinger{}
	nf.compilePayloads()
}

// TestCB2_NucleiFinger_run tests NucleiFinger.run
func TestCB2_NucleiFinger_run(t *testing.T) {
	nf := NucleiFinger{}
	nf.run()
}

// TestCB2_NucleiFinger_StructFields tests NucleiFinger struct fields
func TestCB2_NucleiFinger_StructFields(t *testing.T) {
	nf := NucleiFinger{
		pocPath:      "/path/to/poc.yaml",
		scanRootOnly: true,
	}
	if nf.pocPath != "/path/to/poc.yaml" {
		t.Errorf("Expected pocPath='/path/to/poc.yaml', got '%s'", nf.pocPath)
	}
	if !nf.scanRootOnly {
		t.Error("Expected scanRootOnly=true")
	}
}

// TestCB2_NucleiFinger_StructFields_Default tests NucleiFinger with default values
func TestCB2_NucleiFinger_StructFields_Default(t *testing.T) {
	nf := NucleiFinger{
		pocPath:      "/custom/poc.yaml",
		scanRootOnly: false,
	}
	if nf.pocPath != "/custom/poc.yaml" {
		t.Errorf("Expected pocPath='/custom/poc.yaml', got '%s'", nf.pocPath)
	}
	if nf.scanRootOnly {
		t.Error("Expected scanRootOnly=false")
	}
	if nf.poc != nil {
		t.Error("Expected nil poc")
	}
	if nf.init != nil {
		t.Error("Expected nil init")
	}
}

// TestCB2_YamlFinger_Finger_MultipleSetEntries tests YamlFinger.Finger with multiple set entries
func TestCB2_YamlFinger_Finger_MultipleSetEntries(t *testing.T) {
	poc := &Poc{
		Name:       "multi-set-poc",
		Transport:  "http",
		Expression: "rule1",
		Set: yaml.MapSlice{
			{Key: "var1", Value: "simple_value"},
			{Key: "var2", Value: "another_value"},
			{Key: "reverse", Value: "newReverse()"},
		},
	}
	yf := &YamlFinger{poc: poc}
	f := yf.Finger()
	if f == nil {
		t.Fatal("Finger() returned nil")
	}
	if !f.NeedReverse {
		t.Error("Expected NeedReverse=true when newReverse is in set entries")
	}
}

// TestCB2_YamlFinger_Finger_EmptySet tests YamlFinger.Finger with empty set
func TestCB2_YamlFinger_Finger_EmptySet(t *testing.T) {
	poc := &Poc{
		Name:       "empty-set-poc",
		Transport:  "http",
		Expression: "true",
		Set:        yaml.MapSlice{},
	}
	yf := &YamlFinger{poc: poc}
	f := yf.Finger()
	if f == nil {
		t.Fatal("Finger() returned nil")
	}
	if f.NeedReverse {
		t.Error("Expected NeedReverse=false when set is empty")
	}
}
