/**
* @Author: shaochuyu
* @Date: 6/16/2026 10:00
 */
package sensitivefile

import (
	"context"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/pkg/errors"

	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

// SensitiveFileEntry defines a single sensitive file to detect.
type SensitiveFileEntry struct {
	Name        string `yaml:"name" json:"name"`
	Pattern     string `yaml:"pattern" json:"pattern"`
	Description string `yaml:"description" json:"description"`
	Severity    string `yaml:"severity" json:"severity"`
	patternRe   *regexp.Regexp
}

// Config holds the plugin configuration.
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	MaxDetectPerScan      int `json:"max_detect_per_scan" yaml:"max_detect_per_scan" #:"每次扫描每类最大检测数"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// SensitiveFile is the main plugin struct.
type SensitiveFile struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
	entries       []*SensitiveFileEntry
	detectCounter sync.Map // map[string]*int32 — per-entry atomic counter
}

func (p *SensitiveFile) DefaultConfig() base.PluginConfigInterface {
	config := &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "sensitivefile",
			Enabled: true,
		},
		MaxDetectPerScan: 15,
	}
	return config
}

func (p *SensitiveFile) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin: compiles all content-verification regexes.
func (p *SensitiveFile) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("SensitiveFile init")
	p.PluginMixinInitConfig.Init(ctx, pci, ab)

	p.entries = buildSensitiveFileEntries()

	for _, entry := range p.entries {
		if entry.Pattern != "" {
			re, err := regexp.Compile(entry.Pattern)
			if err != nil {
				logger.Errorf("SensitiveFile: invalid pattern for %s: %v", entry.Name, err)
				entry.patternRe = nil
				continue
			}
			entry.patternRe = re
		}
	}
	return nil
}

// Fingers returns the detection fingers for the plugin.
func (p *SensitiveFile) Fingers() []*base.Finger {
	if len(p.entries) == 0 {
		return nil
	}
	return []*base.Finger{
		{
			Channel:     "web-directory",
			CheckAction: p.CheckAction,
			ExecAction:  p.ExecAction,
			Binding: &model.VulnBinding{
				ID:       "sensitive_file_exposure",
				Plugin:   "sensitivefile",
				Category: "sensitive_file_exposure",
				Severity: model.SeverityHigh,
			},
		},
	}
}

// CheckAction verifies the target URL is a directory path.
func (p *SensitiveFile) CheckAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	u := flow.Request.URL()
	if u == nil {
		return errors.New("no URL in target flow")
	}
	path := u.Path
	// Only trigger on directory paths (ending with / or root path)
	if path == "" || path == "/" || strings.HasSuffix(path, "/") {
		return nil
	}
	return errors.New("not a directory path")
}

// ExecAction scans the current directory for all sensitive files.
func (p *SensitiveFile) ExecAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	baseURL := flow.Request.URL().String()

	// Ensure base URL ends with /
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	// Resolve ${dirname} placeholder: extract directory name from URL
	dirname := extractDirName(baseURL)

	for _, entry := range p.entries {
		if entry.patternRe == nil {
			continue
		}

		// Per-entry execution limit
		key := entry.Name
		counterPtr, _ := p.detectCounter.LoadOrStore(key, new(int32))
		counter := counterPtr.(*int32)
		if atomic.LoadInt32(counter) >= int32(p.GetConfig().(*Config).MaxDetectPerScan) {
			continue
		}

		// Resolve template variables in file name
		fileName := strings.ReplaceAll(entry.Name, "${dirname}", dirname)

		// Build URL
		rawURL := utils.UrlJoinPath(baseURL, fileName)
		request, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			logger.Errorf("SensitiveFile: failed to create request for %s: %v", fileName, err)
			continue
		}

		resp, err := ab.HTTPClient.Respond(context.Background(), request)
		if err != nil {
			continue
		}

		// Only process 200 OK responses
		if resp.StatusCode != 200 {
			continue
		}

		// Content verification: regex must match
		if !entry.patternRe.MatchString(resp.Text) {
			continue
		}

		// Random suffix anti-false-positive: request the same file with a
		// random 5-char suffix appended. If it also returns 200 with similar
		// content, the server is likely a catch-all router → false positive.
		randomSuffix := utils.RandLetters(5)
		testURL := rawURL + randomSuffix
		testReq, err := http.NewRequest("GET", testURL, nil)
		if err != nil {
			continue
		}
		testResp, err := ab.HTTPClient.Respond(context.Background(), testReq)
		if err == nil && testResp.StatusCode == 200 {
			// If the random-suffix URL returns 200, compare bodies.
			// High similarity means catch-all routing → skip this finding.
			if bodySimilarity(resp.Text, testResp.Text) > 0.8 {
				continue
			}
		}

		// Increment counter
		atomic.AddInt32(counter, 1)

		// Report vulnerability
		severity := parseSeverity(entry.Severity)
		v := ab.NewWebVuln(request, resp, nil)
		if v != nil {
			v.SetTargetURL(request.URL())
			v.Payload = fileName
			v.Binding.Severity = severity
			v.Extra["sensitive_file"] = entry.Name
			v.Extra["description"] = entry.Description
			v.Extra["matched_pattern"] = entry.Pattern
			ab.OutputVuln(v)
		}
	}

	return nil
}

// extractDirName extracts the last directory segment from a URL path.
// e.g. "http://example.com/admin/" → "admin"
func extractDirName(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	path := strings.TrimRight(u.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return ""
}

// parseSeverity converts a severity string to model.SeverityLevel.
func parseSeverity(s string) model.SeverityLevel {
	switch strings.ToLower(s) {
	case "critical":
		return model.SeverityCritical
	case "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	case "info":
		return model.SeverityInfo
	default:
		return model.SeverityHigh
	}
}

// bodySimilarity returns a similarity ratio between two strings (0.0-1.0).
// Used for detecting catch-all routing false positives.
func bodySimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	lenA, lenB := len(a), len(b)
	if lenA == 0 && lenB == 0 {
		return 1.0
	}
	if lenA == 0 || lenB == 0 {
		return 0.0
	}
	minLen, maxLen := lenA, lenB
	if minLen > maxLen {
		minLen, maxLen = maxLen, minLen
	}
	lengthRatio := float64(minLen) / float64(maxLen)
	if lengthRatio < 0.5 {
		return lengthRatio * 0.5
	}
	common := 0
	minCheck := minLen
	if minCheck > 512 {
		minCheck = 512
	}
	for i := 0; i < minCheck; i++ {
		if a[i] == b[i] {
			common++
		}
	}
	prefixRatio := float64(common) / float64(minCheck)
	return 0.5*lengthRatio + 0.5*prefixRatio
}

func (p *SensitiveFile) Close() error {
	return nil
}
