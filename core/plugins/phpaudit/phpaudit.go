/**
* @Author: shaochuyu
* @Date: 2026-07-28
*
* phpaudit is an example plugin demonstrating the TechGate helper: it only runs
* its checks when the target is actually serving PHP (detected in real time by
* the wappalyzer engine via base.HasTech). It probes a small set of PHP-specific
* information-exposure endpoints — phpinfo(), the CGI status page, and
* .user.ini config disclosure — that are meaningless on a non-PHP target and
* would otherwise be wasted requests + false positives.
*
* The gate is the point: swap "PHP" for any wappalyzer tech name (Apache, jQuery,
* WordPress, …) and the same shape lets a plugin scope itself to that stack
* without touching the dispatcher or config.
 */
package phpaudit

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

// Config holds the plugin configuration. CheckPaths is the list of PHP-specific
// relative paths to probe; defaults cover the common phpinfo/CGI-status leaks.
// Users can extend or narrow it from config.yaml.
type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	CheckPaths            []string `json:"check_paths" yaml:"check_paths" #:"PHP 信息泄露探测路径列表(相对站点根)"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// PHPAudit is the plugin struct.
type PHPAudit struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose

	// reportedOnce deduplicates per target host: each leak endpoint is reported
	// at most once per host per scan, so a 200-page site doesn't yield 200
	// identical phpinfo findings.
	reportedOnce sync.Map
}

// defaultCheckPaths is the built-in set of PHP-specific information-exposure
// endpoints. Each is only meaningful on a PHP target, which is why the plugin
// is gated on base.HasTech(flow, "PHP") rather than run unconditionally.
var defaultCheckPaths = []string{
	"phpinfo.php", // dedicated phpinfo() page
	"info.php",    // common alternative phpinfo() page
	"php.php",     // another common phpinfo() filename
	"test.php",    // leftover test/info script
	"?phpinfo=1",  // phpinfo() via query (some apps gate on it)
	"phpcgi",      // PHP CGI status / info page
	".user.ini",   // per-dir INI config disclosure (credentials/paths)
	".htaccess",   // (often co-located) rewrite/auth rules leak
}

// phpInfoRe matches the phpinfo() output page: the unmistakable "PHP Version"
// heading plus the phpinfo() CSS class. Body matches are the false-positive
// guard — a bare 200 from a catch-all router won't match.
var phpInfoRe = regexp.MustCompile(`(?i)PHP\s+(?:Version|Info)|phpinfo\(\)|<title>phpinfo<`)

// userIniRe matches a disclosed .user.ini / .htaccess: INI-style directives
// (key=value) or Apache directive lines. Avoids flagging a generic 200.
var userIniRe = regexp.MustCompile(`(?im)^\s*(?:[a-z_][\w.-]*)\s*=\s*\S+|^\s*(?:RewriteRule|Options|Require|SetEnv|php_value|php_flag)\b`)

// cgiStatusRe matches the PHP-FPM / CGI status page (status?json etc.) and the
// text-mode pool-status dump.
var cgiStatusRe = regexp.MustCompile(`(?i)php-fpm|fastcgi|pool\s+stats|processes|request count`)

func (*PHPAudit) Close() error {
	return nil
}

// DefaultConfig returns the default plugin configuration.
func (*PHPAudit) DefaultConfig() base.PluginConfigInterface {
	return &Config{
		PluginBaseConfig: base.PluginBaseConfig{
			Name:    "phpaudit",
			Enabled: true,
		},
		CheckPaths: defaultCheckPaths,
	}
}

// GetConfig returns the resolved plugin configuration.
func (p *PHPAudit) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init initializes the plugin.
func (p *PHPAudit) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("phpaudit init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// Fingers returns the detection rules. The finger subscribes on "web-directory"
// (fires for directory-like URLs, mirroring sensitivefile): from the directory
// base it probes each PHP leak path. The PHP gate lives inside CheckAction so a
// non-PHP target skips every probe — no wasted requests, no false positives.
func (p *PHPAudit) Fingers() []*base.Finger {
	return []*base.Finger{
		{
			Channel:     "web-directory",
			CheckAction: p.checkAction,
			Binding: &model.VulnBinding{
				ID:       "phpaudit/info-leak",
				Plugin:   "phpaudit",
				Category: "phpaudit/info-leak",
				Severity: model.SeverityLow,
			},
		},
	}
}

// reportedKey is the per-host dedup key for a leak path.
func reportedKey(host, path string) string {
	return host + "|" + path
}

// checkAction gates on PHP, then probes each configured leak path from the
// current directory base. Returns nil either way (a skip is not an error).
func (p *PHPAudit) checkAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	if flow == nil || flow.Request == nil {
		return nil
	}
	u := flow.Request.URL()
	if u == nil {
		return nil
	}
	host := u.Hostname()

	// --- the TechGate: only run when the target actually serves PHP ---
	if !base.HasTech(ab, flow, "PHP") {
		return nil
	}

	// Resolve the directory base to probe relative paths against. web-directory
	// delivers directory URLs ending in "/" (or root); normalize so UrlJoinPath
	// treats them as a base.
	baseURL := flow.Request.URL().String()
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	paths := defaultCheckPaths
	if cfg, ok := p.GetConfig().(*Config); ok && cfg != nil && len(cfg.CheckPaths) > 0 {
		paths = cfg.CheckPaths
	}

	for _, pth := range paths {
		// dedup per host+path so a multi-page crawl yields one finding per leak.
		key := reportedKey(host, pth)
		if _, loaded := p.reportedOnce.LoadOrStore(key, struct{}{}); loaded {
			continue
		}

		rawURL := joinBase(baseURL, pth)
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			continue
		}
		resp, err := ab.HTTPClient.Respond(ctx, req)
		if err != nil || resp == nil {
			continue
		}
		if resp.StatusCode != 200 {
			continue
		}
		body := resp.Text
		kind := classifyLeak(pth, body)
		if kind == "" {
			continue
		}

		v := ab.NewWebVuln(req, resp, nil)
		if v != nil {
			v.SetTargetURL(flow.Request.URL())
			v.Payload = pth
			v.Extra["leak_kind"] = kind
			v.Extra["target_tech"] = "PHP"
			ab.OutputVuln(v)
		}
	}
	return nil
}

// classifyLeak maps a probe path + response body to a leak category, returning
// "" when the body doesn't match the expected signature (false-positive guard).
// phpinfo()/.user.ini/.htaccess use body matching; the CGI status query variants
// are validated against the status-page signature.
func classifyLeak(path, body string) string {
	switch {
	case strings.Contains(path, "phpinfo") || strings.HasPrefix(path, "info.php") ||
		strings.HasPrefix(path, "php.php") || strings.HasPrefix(path, "test.php"):
		if phpInfoRe.MatchString(body) {
			return "phpinfo"
		}
	case strings.HasSuffix(path, ".user.ini") || strings.HasSuffix(path, ".htaccess"):
		if userIniRe.MatchString(body) {
			if strings.HasSuffix(path, ".user.ini") {
				return "user_ini_disclosure"
			}
			return "htaccess_disclosure"
		}
	case strings.Contains(path, "phpcgi"):
		if cgiStatusRe.MatchString(body) {
			return "php_cgi_status"
		}
	}
	return ""
}

// joinBase joins a probe path onto a directory base URL. Query-style probes
// ("?phpinfo=1") append to the base path; file-style probes use UrlJoinPath.
func joinBase(baseURL, pth string) string {
	if strings.HasPrefix(pth, "?") {
		return baseURL + pth
	}
	// inline import avoided at top to keep the small join helper self-contained;
	// utils.UrlJoinPath handles leading-slash normalization for us.
	return urlJoinPath(baseURL, pth)
}
