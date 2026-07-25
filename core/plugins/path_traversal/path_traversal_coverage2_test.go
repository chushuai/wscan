package path_traversal

import (
	"context"
	"testing"

	"wscan/core/plugins/base"
)

func TestPathTraversalClose(t *testing.T) {
	pt := &PathTraversal{}
	if err := pt.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestPathTraversalFingersWithInit(t *testing.T) {
	pt := &PathTraversal{}
	cfg := pt.DefaultConfig()
	ab := &base.ApolloBase{}
	pt.Init(context.Background(), cfg, ab)

	fingers := pt.Fingers()
	if len(fingers) == 0 {
		t.Error("Expected at least one finger")
	}
	for i, f := range fingers {
		if f.CheckAction == nil {
			t.Errorf("Finger[%d] has nil CheckAction", i)
		}
		if f.Binding == nil {
			t.Errorf("Finger[%d] has nil Binding", i)
		}
		if f.Channel != "web-generic" {
			t.Errorf("Finger[%d] Channel: expected 'web-generic', got '%s'", i, f.Channel)
		}
	}
}

func TestPathTraversalGetConfigBeforeInit(t *testing.T) {
	pt := &PathTraversal{}
	cfg := pt.GetConfig()
	if cfg != nil {
		t.Errorf("Expected nil config before Init, got %v", cfg)
	}
}

func TestPathTraversalGetConfigAfterInit(t *testing.T) {
	pt := &PathTraversal{}
	cfg := pt.DefaultConfig()
	ab := &base.ApolloBase{}
	pt.Init(context.Background(), cfg, ab)

	cfg = pt.GetConfig()
	if cfg == nil {
		t.Fatal("Expected non-nil config after Init")
	}
	bc := cfg.BaseConfig()
	if bc.Name != "path_traversal" {
		t.Errorf("Expected Name='path_traversal', got '%s'", bc.Name)
	}
}

func TestPathTraversalInitWithNilContext(t *testing.T) {
	pt := &PathTraversal{}
	cfg := pt.DefaultConfig()
	ab := &base.ApolloBase{}

	err := pt.Init(nil, cfg, ab)
	if err != nil {
		t.Errorf("Init() with nil context returned error: %v", err)
	}
}

func TestPathTraversalInitWithBaseContext(t *testing.T) {
	pt := &PathTraversal{}
	cfg := pt.DefaultConfig()
	ab := &base.ApolloBase{}

	err := pt.Init(context.Background(), cfg, ab)
	if err != nil {
		t.Errorf("Init() returned error: %v", err)
	}
}

func TestPathTraversalFingersBindingDetails(t *testing.T) {
	pt := &PathTraversal{}
	pt.PluginMixinInitConfig.Config = pt.DefaultConfig()
	fingers := pt.Fingers()
	if len(fingers) == 0 {
		t.Fatal("Expected at least one finger")
	}
	f := fingers[0]
	if f.Binding.ID != "path-traversal/path-traversal/default" {
		t.Errorf("Expected Binding.ID='path-traversal/path-traversal/default', got '%s'", f.Binding.ID)
	}
	if f.Binding.Plugin != "path-traversal/path-traversal" {
		t.Errorf("Expected Binding.Plugin='path-traversal/path-traversal', got '%s'", f.Binding.Plugin)
	}
	if f.Binding.Category != "path-traversal" {
		t.Errorf("Expected Binding.Category='path-traversal', got '%s'", f.Binding.Category)
	}
}

func TestPathTraversalConfigCustomValues(t *testing.T) {
	cfg := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "path_traversal",
			Enabled: false,
		},
	}
	bc := cfg.BaseConfig()
	if bc.Name != "path_traversal" {
		t.Errorf("Expected Name='path_traversal', got '%s'", bc.Name)
	}
	if bc.Enabled {
		t.Error("Expected Enabled=false")
	}
}

func TestPathTraversalMultipleClose(t *testing.T) {
	pt := &PathTraversal{}
	for i := 0; i < 5; i++ {
		if err := pt.Close(); err != nil {
			t.Errorf("Close() call %d returned error: %v", i, err)
		}
	}
}

func TestPathTraversalMultipleInit(t *testing.T) {
	pt := &PathTraversal{}
	cfg := pt.DefaultConfig()
	ab := &base.ApolloBase{}

	for i := 0; i < 3; i++ {
		err := pt.Init(context.Background(), cfg, ab)
		if err != nil {
			t.Errorf("Init() call %d returned error: %v", i, err)
		}
	}
}

func TestPathTraversalIsValueReplacePayloadAllPrefixes(t *testing.T) {
	// Test all prefixes in the function
	prefixes := []struct {
		prefix   string
		expected bool
	}{
		{"php://filter/read=convert.base64-encode/resource=index", true},
		{"php://input", true},
		{"file:///etc/passwd", true},
		{"file://etc/passwd", true},
		{"ftp://server", false},
		{"data://text", false},
		{"gopher://server", false},
	}

	for _, tt := range prefixes {
		result := isValueReplacePayload(tt.prefix)
		if result != tt.expected {
			t.Errorf("isValueReplacePayload(%q) = %v, want %v", tt.prefix, result, tt.expected)
		}
	}
}
