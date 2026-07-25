package collector

import (
	"testing"

	"wscan/core/utils/checker"
)

func TestAuthCredential_Fields(t *testing.T) {
	cred := AuthCredential{
		Username: "admin",
		Password: "secret",
	}
	if cred.Username != "admin" {
		t.Errorf("expected Username 'admin', got %q", cred.Username)
	}
	if cred.Password != "secret" {
		t.Errorf("expected Password 'secret', got %q", cred.Password)
	}
}

func TestAuthCredential_Empty(t *testing.T) {
	cred := AuthCredential{}
	if cred.Username != "" {
		t.Errorf("expected empty Username, got %q", cred.Username)
	}
	if cred.Password != "" {
		t.Errorf("expected empty Password, got %q", cred.Password)
	}
}

func TestCrawlerCommonConfig_Defaults(t *testing.T) {
	cfg := CrawlerCommonConfig{}
	if cfg.BasicCrawler.MaxDepth != 0 {
		t.Errorf("expected default MaxDepth 0, got %d", cfg.BasicCrawler.MaxDepth)
	}
	if cfg.BasicCrawler.MaxCountOfLinks != 0 {
		t.Errorf("expected default MaxCountOfLinks 0, got %d", cfg.BasicCrawler.MaxCountOfLinks)
	}
	if cfg.BasicCrawler.AllowVisitParentPath != false {
		t.Errorf("expected default AllowVisitParentPath false, got %v", cfg.BasicCrawler.AllowVisitParentPath)
	}
}

func TestCrawlerCommonConfig_WithBasicAuth(t *testing.T) {
	cfg := CrawlerCommonConfig{
		BasicAuth: AuthCredential{
			Username: "user",
			Password: "pass",
		},
	}
	if cfg.BasicAuth.Username != "user" {
		t.Errorf("expected Username 'user', got %q", cfg.BasicAuth.Username)
	}
	if cfg.BasicAuth.Password != "pass" {
		t.Errorf("expected Password 'pass', got %q", cfg.BasicAuth.Password)
	}
}

func TestCrawlerCommonConfig_WithRestriction(t *testing.T) {
	restriction := &checker.RequestCheckerConfig{}
	cfg := CrawlerCommonConfig{
		Restriction: restriction,
	}
	if cfg.Restriction != restriction {
		t.Error("expected Restriction to be set")
	}
}

func TestCrawlerCommonConfig_NilRestriction(t *testing.T) {
	cfg := CrawlerCommonConfig{}
	if cfg.Restriction != nil {
		t.Error("expected default Restriction to be nil")
	}
}

func TestBasicCrawlerConfig_Values(t *testing.T) {
	cfg := BasicCrawlerConfig{
		MaxDepth:             5,
		MaxCountOfLinks:      100,
		AllowVisitParentPath: true,
	}
	if cfg.MaxDepth != 5 {
		t.Errorf("expected MaxDepth 5, got %d", cfg.MaxDepth)
	}
	if cfg.MaxCountOfLinks != 100 {
		t.Errorf("expected MaxCountOfLinks 100, got %d", cfg.MaxCountOfLinks)
	}
	if cfg.AllowVisitParentPath != true {
		t.Errorf("expected AllowVisitParentPath true, got %v", cfg.AllowVisitParentPath)
	}
}

func TestBrowserConfig_Defaults(t *testing.T) {
	cfg := BrowserConfig{}
	if cfg.ExecPath != "" {
		t.Errorf("expected empty ExecPath, got %q", cfg.ExecPath)
	}
	if cfg.DisableHeadless != false {
		t.Errorf("expected default DisableHeadless false, got %v", cfg.DisableHeadless)
	}
	if cfg.ForceSandbox != false {
		t.Errorf("expected default ForceSandbox false, got %v", cfg.ForceSandbox)
	}
	if cfg.EnableImage != false {
		t.Errorf("expected default EnableImage false, got %v", cfg.EnableImage)
	}
	if cfg.Trace != false {
		t.Errorf("expected default Trace false, got %v", cfg.Trace)
	}
	if cfg.ParentPathDetect != false {
		t.Errorf("expected default ParentPathDetect false, got %v", cfg.ParentPathDetect)
	}
	if cfg.Width != 0 {
		t.Errorf("expected default Width 0, got %d", cfg.Width)
	}
	if cfg.Height != 0 {
		t.Errorf("expected default Height 0, got %d", cfg.Height)
	}
	if cfg.NavigateTimeoutSecond != 0 {
		t.Errorf("expected default NavigateTimeoutSecond 0, got %d", cfg.NavigateTimeoutSecond)
	}
	if cfg.LoadTimeoutSecond != 0 {
		t.Errorf("expected default LoadTimeoutSecond 0, got %d", cfg.LoadTimeoutSecond)
	}
	if cfg.Retry != 0 {
		t.Errorf("expected default Retry 0, got %d", cfg.Retry)
	}
	if cfg.MaxInteractive != 0 {
		t.Errorf("expected default MaxInteractive 0, got %d", cfg.MaxInteractive)
	}
	if cfg.MaxInteractiveDepth != 0 {
		t.Errorf("expected default MaxInteractiveDepth 0, got %d", cfg.MaxInteractiveDepth)
	}
	if cfg.MaxPageConcurrent != 0 {
		t.Errorf("expected default MaxPageConcurrent 0, got %d", cfg.MaxPageConcurrent)
	}
	if cfg.MaxPageVisit != 0 {
		t.Errorf("expected default MaxPageVisit 0, got %d", cfg.MaxPageVisit)
	}
	if cfg.MaxPageVisitPerSite != 0 {
		t.Errorf("expected default MaxPageVisitPerSite 0, got %d", cfg.MaxPageVisitPerSite)
	}
	if cfg.MaxJSRedirect != 0 {
		t.Errorf("expected default MaxJSRedirect 0, got %d", cfg.MaxJSRedirect)
	}
	if cfg.ElementFilterStrength != 0 {
		t.Errorf("expected default ElementFilterStrength 0, got %d", cfg.ElementFilterStrength)
	}
	if cfg.NewTaskDeduplicationOption != 0 {
		t.Errorf("expected default NewTaskDeduplicationOption 0, got %d", cfg.NewTaskDeduplicationOption)
	}
	if cfg.OutputDeduplicationOption != 0 {
		t.Errorf("expected default OutputDeduplicationOption 0, got %d", cfg.OutputDeduplicationOption)
	}
	if cfg.SendFormPost != false {
		t.Errorf("expected default SendFormPost false, got %v", cfg.SendFormPost)
	}
}

func TestBrowserConfig_WithValues(t *testing.T) {
	cfg := BrowserConfig{
		ExecPath:                   "/usr/bin/chrome",
		DisableHeadless:            true,
		ForceSandbox:               true,
		EnableImage:                true,
		DisallowedResourceType:     []string{"stylesheet", "font"},
		Trace:                      true,
		ParentPathDetect:           true,
		Monitor:                    "http://localhost:9222",
		MaxDepth:                   3,
		Width:                      1280,
		Height:                     720,
		NavigateTimeoutSecond:      30,
		LoadTimeoutSecond:          20,
		Retry:                      2,
		PageAnalyzeTimeoutSecond:   10,
		MaxInteractive:             50,
		MaxInteractiveDepth:        3,
		MaxPageConcurrent:          5,
		MaxPageVisit:               100,
		MaxPageVisitPerSite:        20,
		MaxJSRedirect:              5,
		DefaultURLs:                []string{"/robots.txt", "/sitemap.xml"},
		TabInitJS:                  "console.log('init')",
		ElementFilterStrength:      3,
		NewTaskDeduplicationOption: 1,
		OutputDeduplicationOption:  2,
		SendFormPost:               true,
	}
	if cfg.ExecPath != "/usr/bin/chrome" {
		t.Errorf("expected ExecPath '/usr/bin/chrome', got %q", cfg.ExecPath)
	}
	if cfg.DisableHeadless != true {
		t.Errorf("expected DisableHeadless true, got %v", cfg.DisableHeadless)
	}
	if len(cfg.DisallowedResourceType) != 2 {
		t.Errorf("expected 2 DisallowedResourceType, got %d", len(cfg.DisallowedResourceType))
	}
	if cfg.MaxDepth != 3 {
		t.Errorf("expected MaxDepth 3, got %d", cfg.MaxDepth)
	}
	if cfg.Width != 1280 {
		t.Errorf("expected Width 1280, got %d", cfg.Width)
	}
	if cfg.Height != 720 {
		t.Errorf("expected Height 720, got %d", cfg.Height)
	}
	if cfg.ElementFilterStrength != 3 {
		t.Errorf("expected ElementFilterStrength 3, got %d", cfg.ElementFilterStrength)
	}
	if len(cfg.DefaultURLs) != 2 {
		t.Errorf("expected 2 DefaultURLs, got %d", len(cfg.DefaultURLs))
	}
	if cfg.SendFormPost != true {
		t.Errorf("expected SendFormPost true, got %v", cfg.SendFormPost)
	}
}

func TestMitmConfig_Defaults(t *testing.T) {
	cfg := MitmConfig{}
	if cfg.Listen != "" {
		t.Errorf("expected empty Listen, got %q", cfg.Listen)
	}
	if cfg.CACert != "" {
		t.Errorf("expected empty CACert, got %q", cfg.CACert)
	}
	if cfg.CAKey != "" {
		t.Errorf("expected empty CAKey, got %q", cfg.CAKey)
	}
	if cfg.DownstreamProxy != "" {
		t.Errorf("expected empty DownstreamProxy, got %q", cfg.DownstreamProxy)
	}
	if cfg.WebCtrlPage != "" {
		t.Errorf("expected empty WebCtrlPage, got %q", cfg.WebCtrlPage)
	}
	if cfg.TTL != 0 {
		t.Errorf("expected TTL 0, got %d", cfg.TTL)
	}
	if cfg.Restriction != nil {
		t.Error("expected default Restriction to be nil")
	}
	if len(cfg.AllowIPRange) != 0 {
		t.Errorf("expected empty AllowIPRange, got %d items", len(cfg.AllowIPRange))
	}
}

func TestMitmConfig_WithValues(t *testing.T) {
	cfg := MitmConfig{
		Listen:          "127.0.0.1:8080",
		CACert:          "/path/to/ca.crt",
		CAKey:           "/path/to/ca.key",
		DownstreamProxy: "http://proxy:3128",
		WebCtrlPage:     "/ctrl",
		TTL:             3600,
		AllowIPRange:    []string{"192.168.1.0/24", "10.0.0.1"},
		ProxyAuth: AuthCredential{
			Username: "proxyuser",
			Password: "proxypass",
		},
	}
	if cfg.Listen != "127.0.0.1:8080" {
		t.Errorf("expected Listen '127.0.0.1:8080', got %q", cfg.Listen)
	}
	if cfg.CACert != "/path/to/ca.crt" {
		t.Errorf("expected CACert '/path/to/ca.crt', got %q", cfg.CACert)
	}
	if cfg.DownstreamProxy != "http://proxy:3128" {
		t.Errorf("expected DownstreamProxy 'http://proxy:3128', got %q", cfg.DownstreamProxy)
	}
	if cfg.TTL != 3600 {
		t.Errorf("expected TTL 3600, got %d", cfg.TTL)
	}
	if len(cfg.AllowIPRange) != 2 {
		t.Errorf("expected 2 AllowIPRange, got %d", len(cfg.AllowIPRange))
	}
	if cfg.ProxyAuth.Username != "proxyuser" {
		t.Errorf("expected ProxyAuth Username 'proxyuser', got %q", cfg.ProxyAuth.Username)
	}
}

func TestMitmProxyHeaderConfig_Defaults(t *testing.T) {
	cfg := MitmProxyHeaderConfig{}
	if cfg.Via != "" {
		t.Errorf("expected empty Via, got %q", cfg.Via)
	}
	if cfg.XForwarded != false {
		t.Errorf("expected default XForwarded false, got %v", cfg.XForwarded)
	}
}

func TestMitmProxyHeaderConfig_WithValues(t *testing.T) {
	cfg := MitmProxyHeaderConfig{
		Via:        "1.1 proxy",
		XForwarded: true,
	}
	if cfg.Via != "1.1 proxy" {
		t.Errorf("expected Via '1.1 proxy', got %q", cfg.Via)
	}
	if cfg.XForwarded != true {
		t.Errorf("expected XForwarded true, got %v", cfg.XForwarded)
	}
}

func TestMitmQueueConfig_Defaults(t *testing.T) {
	cfg := MitmQueueConfig{}
	if cfg.MaxLength != 0 {
		t.Errorf("expected default MaxLength 0, got %d", cfg.MaxLength)
	}
}

func TestMitmQueueConfig_WithValues(t *testing.T) {
	cfg := MitmQueueConfig{
		MaxLength: 5000,
	}
	if cfg.MaxLength != 5000 {
		t.Errorf("expected MaxLength 5000, got %d", cfg.MaxLength)
	}
}
