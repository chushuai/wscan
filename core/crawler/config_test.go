package crawler

import (
	"testing"
	"time"
)

func TestConfigCorrect(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{"nil config", nil, true},
		{"valid defaults", &Config{}, false},
		{"negative depth", &Config{MaxDepth: -1}, false}, // corrected to 0
		{"negative max URLs", &Config{MaxCountOfURLs: -1}, false},
		{"zero max concurrent", &Config{MaxConcurrent: 0}, false},   // corrected to 10
		{"too large concurrent", &Config{MaxConcurrent: 20}, false}, // corrected to 10
		{"valid auth", &Config{
			AuthConfig: AuthConfig{
				BasicAuth: &BasicAuth{Username: "user", Password: "pass"},
			},
		}, false},
		{"invalid auth missing username", &Config{
			AuthConfig: AuthConfig{
				BasicAuth: &BasicAuth{Username: "", Password: "pass"},
			},
		}, true},
		{"invalid auth missing password", &Config{
			AuthConfig: AuthConfig{
				BasicAuth: &BasicAuth{Username: "user", Password: ""},
			},
		}, true},
		{"invalid form auth missing URL", &Config{
			AuthConfig: AuthConfig{
				FormAuth: &FormAuth{URL: "", Username: "user", Password: "pass"},
			},
		}, true},
		{"valid form auth", &Config{
			AuthConfig: AuthConfig{
				FormAuth: &FormAuth{URL: "http://example.com/login", Username: "user", Password: "pass"},
			},
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.config.Correct()
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result == nil && tt.config != nil {
					t.Error("corrected config should not be nil")
				}
			}
		})
	}
}

func TestConfigCorrectDefaults(t *testing.T) {
	c := &Config{}
	corrected, err := c.Correct()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if corrected.MaxConcurrent != 10 {
		t.Errorf("MaxConcurrent should default to 10, got %d", corrected.MaxConcurrent)
	}
	if corrected.LoadWait != 5 {
		t.Errorf("LoadWait should default to 5, got %d", corrected.LoadWait)
	}
	if corrected.MaxCountOfURLs != MaxCrawlCount {
		t.Errorf("MaxCountOfURLs should default to %d, got %d", MaxCrawlCount, corrected.MaxCountOfURLs)
	}
}

func TestCrawlerConfigBrowserFields(t *testing.T) {
	c := &Config{
		Browser:                  true,
		ExecPath:                 "/usr/bin/chromium",
		DisableHeadless:          false,
		ForceSandbox:             true,
		WindowWidth:              1280,
		WindowHeight:             720,
		NavigateTimeoutSecond:    30,
		LoadTimeoutSecond:        20,
		Retry:                    3,
		PageAnalyzeTimeoutSecond: 15,
		MaxInteractive:           10,
		MaxInteractiveDepth:      5,
		MaxPageVisitPerSite:      100,
		ElementFilterStrength:    3,
		ParentPathDetect:         true,
		AllowVisitParentPath:     true,
	}

	// Verify all new fields are present in Config struct
	if c.ForceSandbox != true {
		t.Error("ForceSandbox should be set")
	}
	if c.WindowWidth != 1280 {
		t.Error("WindowWidth should be 1280")
	}
	if c.WindowHeight != 720 {
		t.Error("WindowHeight should be 720")
	}
	if c.NavigateTimeoutSecond != 30 {
		t.Error("NavigateTimeoutSecond should be 30")
	}
	if c.Retry != 3 {
		t.Error("Retry should be 3")
	}
	if c.MaxInteractive != 10 {
		t.Error("MaxInteractive should be 10")
	}
	if c.MaxPageVisitPerSite != 100 {
		t.Error("MaxPageVisitPerSite should be 100")
	}
	if c.AllowVisitParentPath != true {
		t.Error("AllowVisitParentPath should be true")
	}
}

func TestNewCrawlerTaskConfig(t *testing.T) {
	c := &Config{
		MaxConcurrent:         5,
		MaxDepth:              10,
		MaxCountOfURLs:        200,
		NavigateTimeoutSecond: 30,
		LoadTimeoutSecond:     15,
		Retry:                 2,
		MaxPageVisitPerSite:   50,
		ParentPathDetect:      true,
		ElementFilterStrength: 4,
	}

	corrected, err := c.Correct()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	crawler := NewCrawler(*corrected, nil)

	// Check that TaskConfig is populated from browser config
	if crawler.config == nil {
		t.Fatal("config should not be nil")
	}
	tc := crawler.config.TaskConfig
	if tc == nil {
		t.Fatal("TaskConfig should not be nil")
	}

	// NavigateTimeoutSecond should map to TabRunTimeout
	expectedTabRun := 30 * time.Second
	if tc.TabRunTimeout != expectedTabRun {
		t.Errorf("TabRunTimeout should be %v, got %v", expectedTabRun, tc.TabRunTimeout)
	}

	// LoadTimeoutSecond should map to DomContentLoadedTimeout
	expectedDom := 15 * time.Second
	if tc.DomContentLoadedTimeout != expectedDom {
		t.Errorf("DomContentLoadedTimeout should be %v, got %v", expectedDom, tc.DomContentLoadedTimeout)
	}

	// MaxCrawlCount should match MaxCountOfURLs
	if tc.MaxCrawlCount != 200 {
		t.Errorf("MaxCrawlCount should be 200, got %d", tc.MaxCrawlCount)
	}
}
