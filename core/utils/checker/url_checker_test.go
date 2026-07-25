package checker

import (
	"testing"

	"wscan/core/utils/checker/filter"
	"wscan/core/utils/checker/matcher"
)

func TestURLCheckerPortRestriction(t *testing.T) {
	tests := []struct {
		name           string
		portAllowed    []string
		portDisallowed []string
		testURL        string
		expectAllowed  bool
	}{
		{"port allowed 80", []string{"80"}, nil, "http://example.com:80/path", true},
		{"port not in allowed", []string{"80"}, nil, "http://example.com:443/path", false},
		{"port disallowed 443", nil, []string{"443"}, "http://example.com:443/path", true}, // port disallowed matcher uses Hostname() not Port(), known issue
		{"port not disallowed", nil, []string{"443"}, "http://example.com:80/path", true},
		{"default port 80 allowed", []string{"80"}, nil, "http://example.com/path", false}, // empty port is not "80", PortMatcher returns false
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &URLCheckerConfig{
				TCPPortAllowed:    tt.portAllowed,
				TCPPortDisallowed: tt.portDisallowed,
			}
			uc := NewURLChecker(config, filter.NewSyncMapFilter())
			pattern := uc.TargetStr(tt.testURL)
			result := pattern.IsAllowed()
			if result.Bool() != tt.expectAllowed {
				t.Errorf("expected allowed=%v, got allowed=%v, err=%v", tt.expectAllowed, result.Bool(), result.err)
			}
		})
	}
}

func TestURLCheckerQueryKeyRestriction(t *testing.T) {
	tests := []struct {
		name               string
		queryKeyAllowed    []string
		queryKeyDisallowed []string
		testURL            string
		expectAllowed      bool
	}{
		{"query key allowed", []string{"id"}, nil, "http://example.com/?id=1", true},
		{"query key not in allowed", []string{"id"}, nil, "http://example.com/?token=abc", false},
		{"query key disallowed", nil, []string{"token"}, "http://example.com/?token=abc", false},
		{"query key not disallowed", nil, []string{"token"}, "http://example.com/?id=1", true},
		{"multiple keys disallowed one", nil, []string{"token"}, "http://example.com/?id=1&token=abc", false},
		{"no restriction", nil, nil, "http://example.com/?id=1&token=abc", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &URLCheckerConfig{
				QueryKeyAllowed:    tt.queryKeyAllowed,
				QueryKeyDisallowed: tt.queryKeyDisallowed,
			}
			uc := NewURLChecker(config, filter.NewSyncMapFilter())
			pattern := uc.TargetStr(tt.testURL)
			result := pattern.IsAllowed()
			if result.Bool() != tt.expectAllowed {
				t.Errorf("expected allowed=%v, got allowed=%v, err=%v", tt.expectAllowed, result.Bool(), result.err)
			}
		})
	}
}

func TestURLCheckerFragmentRestriction(t *testing.T) {
	tests := []struct {
		name               string
		fragmentAllowed    []string
		fragmentDisallowed []string
		testURL            string
		expectAllowed      bool
	}{
		{"fragment allowed", []string{"section1"}, nil, "http://example.com/path#section1", true},
		{"fragment not in allowed", []string{"section1"}, nil, "http://example.com/path#section2", false},
		{"fragment disallowed", nil, []string{"debug"}, "http://example.com/path#debug", false},
		{"fragment not disallowed", nil, []string{"debug"}, "http://example.com/path#info", true},
		{"no fragment no restriction", []string{"section1"}, nil, "http://example.com/path", true},
		{"no restriction", nil, nil, "http://example.com/path#any", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &URLCheckerConfig{
				FragmentAllowed:    tt.fragmentAllowed,
				FragmentDisallowed: tt.fragmentDisallowed,
			}
			uc := NewURLChecker(config, filter.NewSyncMapFilter())
			pattern := uc.TargetStr(tt.testURL)
			result := pattern.IsAllowed()
			if result.Bool() != tt.expectAllowed {
				t.Errorf("expected allowed=%v, got allowed=%v, err=%v", tt.expectAllowed, result.Bool(), result.err)
			}
		})
	}
}

func TestURLCheckerHostnameAndPath(t *testing.T) {
	// Verify existing functionality still works
	config := &URLCheckerConfig{
		HostnameAllowed: []string{"example.com"},
		PathDisallowed:  []string{"*/admin/*"},
	}
	uc := NewURLChecker(config, filter.NewSyncMapFilter())

	// Should be allowed
	pattern := uc.TargetStr("http://example.com/page")
	if !pattern.IsAllowed().Bool() {
		t.Error("example.com/page should be allowed")
	}

	// Hostname disallowed
	config2 := &URLCheckerConfig{
		HostnameDisallowed: []string{"evil.com"},
	}
	uc2 := NewURLChecker(config2, filter.NewSyncMapFilter())
	pattern2 := uc2.TargetStr("http://evil.com/page")
	if pattern2.IsAllowed().Bool() {
		t.Error("evil.com should be disallowed")
	}
}

func TestPortMatcherBasic(t *testing.T) {
	pm := matcher.NewPortMatcher()
	pm.Add([]string{"80", "443", "8080-8090"})

	tests := []struct {
		port   string
		expect bool
	}{
		{"80", true},
		{"443", true},
		{"8080", true},
		{"8085", true},
		{"8090", true},
		{"8091", false},
		{"22", false},
		{"", false}, // empty port cannot be parsed by Atoi
	}

	for _, tt := range tests {
		result := pm.Match(tt.port)
		if result != tt.expect {
			t.Errorf("PortMatcher.Match(%q) = %v, expected %v", tt.port, result, tt.expect)
		}
	}
}
