package plugins

import (
	"testing"
)

// ==================== GetPluginByName ====================

func TestGetPluginByName_ExistingPlugin(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"xss"},
		{"path_traversal"},
		{"sqldet"},
		{"crlf-injection"},
		{"jsonp"},
		{"dirscan"},
		{"prometheus"},
		{"waftest"},
		{"cmd-injection"},
		{"brute-force"},
		{"ssrf"},
		{"swagger"},
		{"custom"},
		{"baseline"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := GetPluginByName(tt.name)
			if p == nil {
				t.Errorf("GetPluginByName(%q) returned nil", tt.name)
			} else {
				cfg := p.DefaultConfig()
				if cfg == nil {
					t.Errorf("GetPluginByName(%q): DefaultConfig() returned nil", tt.name)
				} else {
					bc := cfg.BaseConfig()
					if bc == nil {
						t.Errorf("GetPluginByName(%q): BaseConfig() returned nil", tt.name)
					}
				}
			}
		})
	}
}

func TestGetPluginByName_NonExistentPlugin(t *testing.T) {
	p := GetPluginByName("nonexistent")
	if p != nil {
		t.Errorf("GetPluginByName('nonexistent') should return nil, got %v", p)
	}
}

func TestGetPluginByName_EmptyString(t *testing.T) {
	p := GetPluginByName("")
	if p != nil {
		t.Errorf("GetPluginByName('') should return nil, got %v", p)
	}
}

// ==================== All ====================

func TestAll_ReturnsAllPlugins(t *testing.T) {
	plugins := All()
	if len(plugins) == 0 {
		t.Error("All() should return at least one plugin")
	}

	// Verify each plugin has a valid DefaultConfig
	for _, p := range plugins {
		cfg := p.DefaultConfig()
		if cfg == nil {
			t.Error("Plugin DefaultConfig() returned nil")
			continue
		}
		bc := cfg.BaseConfig()
		if bc == nil {
			t.Error("Plugin BaseConfig() returned nil")
			continue
		}
		if bc.Name == "" {
			t.Error("Plugin Name should not be empty")
		}
	}
}

func TestAll_AllPluginsHaveUniqueNames(t *testing.T) {
	plugins := All()
	names := make(map[string]bool)
	for _, p := range plugins {
		cfg := p.DefaultConfig()
		if cfg == nil {
			continue
		}
		bc := cfg.BaseConfig()
		if bc == nil {
			continue
		}
		if names[bc.Name] {
			t.Errorf("Duplicate plugin name: %s", bc.Name)
		}
		names[bc.Name] = true
	}
}

func TestAll_AllPluginsCanClose(t *testing.T) {
	plugins := All()
	for _, p := range plugins {
		if err := p.Close(); err != nil {
			cfg := p.DefaultConfig()
			name := "unknown"
			if cfg != nil && cfg.BaseConfig() != nil {
				name = cfg.BaseConfig().Name
			}
			t.Errorf("Plugin %s Close() error: %v", name, err)
		}
	}
}

func TestAll_ExpectedPluginCount(t *testing.T) {
	plugins := All()
	// Count of all registered plugins
	if len(plugins) < 20 {
		t.Errorf("Expected at least 20 plugins, got %d", len(plugins))
	}
}
