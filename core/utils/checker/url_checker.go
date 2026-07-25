/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package checker

import (
	"fmt"
	"net/url"
	"wscan/core/utils/checker/filter"
	"wscan/core/utils/checker/matcher"
	"wscan/core/utils/log"

	"github.com/pkg/errors"
)

type URLCheckerConfig struct {
	SchemeAllowed        []string `json:"scheme_allowed" yaml:"-"`
	SchemeDisallowed     []string `json:"scheme_disallowed" yaml:"-"`
	HostnameAllowed      []string `json:"hostname_allowed" yaml:"hostname_allowed" #:"允许访问的 Hostname，支持格式如 t.com、*.t.com、1.1.1.1、1.1.1.1/24、1.1-4.1.1-8"`
	HostnameDisallowed   []string `json:"hostname_disallowed" yaml:"hostname_disallowed" #:"不允许访问的 Hostname，支持格式如 t.com、*.t.com、1.1.1.1、1.1.1.1/24、1.1-4.1.1-8"`
	TCPPortAllowed       []string `json:"port_allowed" yaml:"port_allowed" #:"允许访问的端口, 支持的格式如: 80、80-85"`
	TCPPortDisallowed    []string `json:"port_disallowed" yaml:"port_disallowed" #:"不允许访问的端口, 支持的格式如: 80、80-85"`
	PathAllowed          []string `json:"path_allowed" yaml:"path_allowed" #:"允许访问的路径，支持的格式如: test、*test*"`
	PathDisallowed       []string `json:"path_disallowed" yaml:"path_disallowed" #:"不允许访问的路径, 支持的格式如: test、*test*"`
	PathSuffixAllowed    []string `json:"path_suffix_allowed" yaml:"-"`
	PathSuffixDisallowed []string `json:"path_suffix_disallowed" yaml:"-"`
	QueryKeyAllowed      []string `json:"query_key_allowed" yaml:"query_key_allowed" #:"允许访问的 Query Key，支持的格式如: test、*test*"`
	QueryKeyDisallowed   []string `json:"query_key_disallowed" yaml:"query_key_disallowed" #:"不允许访问的 Query Key, 支持的格式如: test、*test*"`
	QueryRawAllowed      []string `json:"query_raw_allowed" yaml:"-"`
	QueryRawDisallowed   []string `json:"query_raw_disallowed" yaml:"-"`
	FragmentAllowed      []string `json:"fragment_allowed" yaml:"fragment_allowed" #:"允许访问的 Fragment, 支持的格式如: test、*test*"`
	FragmentDisallowed   []string `json:"fragment_disallowed" yaml:"fragment_disallowed" #:"不允许访问的 Fragment, 支持的格式如: test、*test*"`
	URLRegexAllowed      []string `json:"url_regex_allowed" yaml:"-"`
	URLRegexDisallowed   []string `json:"url_regex_disallowed" yaml:"-"`
	URLGlobAllowed       []string `json:"url_glob_allowed" yaml:"-"`
	URLGlobDisallowed    []string `json:"url_glob_disallowed" yaml:"-"`
}

type URLChecker struct {
	filter.Filter
	config                      *URLCheckerConfig
	SchemeAllowedMatcher        *matcher.KeyMatcher
	SchemeDisallowedMatcher     *matcher.KeyMatcher
	HostnameAllowedMatcher      *matcher.HostsMatcher
	HostnameDisallowedMatcher   *matcher.HostsMatcher
	TCPPortAllowedMatcher       *matcher.PortMatcher
	TCPPortDisallowedMatcher    *matcher.PortMatcher
	PathAllowedMatcher          *matcher.GlobMatcher
	PathDisallowedMatcher       *matcher.GlobMatcher
	PathSuffixAllowedMatcher    *matcher.KeyMatcher
	PathSuffixDisallowedMatcher *matcher.KeyMatcher
	QueryKeyAllowedMatcher      *matcher.GlobMatcher
	QueryKeyDisallowedMatcher   *matcher.GlobMatcher
	QueryRawAllowedMatcher      *matcher.GlobMatcher
	QueryRawDisallowedMatcher   *matcher.GlobMatcher
	FragmentAllowedMatcher      *matcher.GlobMatcher
	FragmentDisallowedMatcher   *matcher.GlobMatcher
	URLRegexAllowedMatcher      *matcher.RegexpMatcher
	URLRegexDisallowedMatcher   *matcher.RegexpMatcher
	URLGlobAllowedMatcher       *matcher.GlobMatcher
	URLGlobDisallowedMatcher    *matcher.GlobMatcher
	Scope                       string
	AutoInsertDisabled          bool
	TTL                         int64
}

type URLPattern struct {
	Checker            *URLChecker
	err                error
	urlStr             string
	URL                *url.URL
	Scope              string
	AutoInsertDisabled bool
	TTL                int64
}

func (up *URLPattern) AddScope(scope string) *URLPattern {
	up.Scope += scope
	return up
}

// Bool() 方法返回 URLPattern 对象的 error 是否为 nil，如果是，则返回 true，否则返回 false。
func (up *URLPattern) Bool() bool {
	return up.err == nil
}

// 该方法将URLPattern的AutoInsertDisabled字段设为true，并返回URLPattern对象。
func (up *URLPattern) DisableAutoInsert() *URLPattern {
	up.AutoInsertDisabled = true
	return up
}

// IsAllowed 返回当前URLPattern是否允许通过。
func (up *URLPattern) IsAllowed() *URLPattern {
	// 如果当前URLPattern没有错误，并且其对应的检查器不为nil，则调用其IsAllowed方法判断是否允许通过。
	if up.err == nil && up.Checker != nil {
		if !up.Checker.HostnameAllowedMatcher.IsEmpty() {
			if !up.Checker.HostnameAllowedMatcher.Match(up.URL.Hostname()) {
				up.err = errors.Errorf("HostnameDisallowed %s", up.URL.Hostname())
				log.Info(up.err.Error())
				return up
			}
		}
		if !up.Checker.HostnameDisallowedMatcher.IsEmpty() {
			if up.Checker.HostnameDisallowedMatcher.Match(up.URL.Hostname()) {
				up.err = errors.Errorf("HostnameDisallowed %s", up.URL.Hostname())
				return up
			}
		}
		if !up.Checker.PathAllowedMatcher.IsEmpty() {
			if !up.Checker.PathAllowedMatcher.Match(up.URL.RequestURI()) {
				up.err = errors.Errorf("PathDisallowed %s", up.URL.RequestURI())
				return up
			}
		}
		if !up.Checker.PathDisallowedMatcher.IsEmpty() {
			if up.Checker.PathDisallowedMatcher.Match(up.URL.RequestURI()) {
				up.err = errors.Errorf("PathDisallowed %s", up.URL.RequestURI())
				return up
			}
		}
		// Port restriction
		if !up.Checker.TCPPortAllowedMatcher.IsEmpty() {
			if !up.Checker.TCPPortAllowedMatcher.Match(up.URL.Port()) {
				up.err = errors.Errorf("PortDisallowed %s", up.URL.Host)
				log.Info(up.err.Error())
				return up
			}
		}
		if !up.Checker.TCPPortDisallowedMatcher.IsEmpty() {
			if up.Checker.TCPPortDisallowedMatcher.Match(up.URL.Hostname()) {
				up.err = errors.Errorf("PortDisallowed %s", up.URL.Host)
				return up
			}
		}
		// Query key restriction
		if !up.Checker.QueryKeyAllowedMatcher.IsEmpty() || !up.Checker.QueryKeyDisallowedMatcher.IsEmpty() {
			for key := range up.URL.Query() {
				if !up.Checker.QueryKeyAllowedMatcher.IsEmpty() {
					if !up.Checker.QueryKeyAllowedMatcher.Match(key) {
						up.err = errors.Errorf("QueryKeyDisallowed %s", key)
						log.Info(up.err.Error())
						return up
					}
				}
				if !up.Checker.QueryKeyDisallowedMatcher.IsEmpty() {
					if up.Checker.QueryKeyDisallowedMatcher.Match(key) {
						up.err = errors.Errorf("QueryKeyDisallowed %s", key)
						return up
					}
				}
			}
		}
		// Fragment restriction
		if up.URL.Fragment != "" {
			if !up.Checker.FragmentAllowedMatcher.IsEmpty() {
				if !up.Checker.FragmentAllowedMatcher.Match(up.URL.Fragment) {
					up.err = errors.Errorf("FragmentDisallowed %s", up.URL.Fragment)
					log.Info(up.err.Error())
					return up
				}
			}
			if !up.Checker.FragmentDisallowedMatcher.IsEmpty() {
				if up.Checker.FragmentDisallowedMatcher.Match(up.URL.Fragment) {
					up.err = errors.Errorf("FragmentDisallowed %s", up.URL.Fragment)
					return up
				}
			}
		}
	}
	return up
}

func NoQueryUrl(u *url.URL) string {
	return fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, u.Path)
}

func (up *URLPattern) IsNewWebsiteDir() *URLPattern {
	key := fmt.Sprintf("web_dir_%s", NoQueryUrl(up.URL))
	if up.Checker.Filter.IsInserted(key, true, 0) {
		return nil
	}
	log.Infof("new website dir: %s", NoQueryUrl(up.URL))
	return up
}

func (up *URLPattern) IsNewWebsitePath() *URLPattern {
	key := fmt.Sprintf("web_path_%s", NoQueryUrl(up.URL))
	if up.Checker.Filter.IsInserted(key, true, 0) {
		return nil
	}
	log.Infof("new path dir: %s", NoQueryUrl(up.URL))
	return up
}

func (up *URLPattern) IsNewWebsite() *URLPattern {
	key := fmt.Sprintf("website_%s://%s", up.URL.Scheme, up.URL.Host)
	if up.Checker.Filter.IsInserted(key, true, 0) {
		return nil
	}
	log.Infof("new website: %s://%s", up.URL.Scheme, up.URL.Host)
	return up
}

func (up *URLPattern) IsNewHostPort() *URLPattern {
	return up
}

func (up *URLPattern) IsNewWebsiteQueryKey() *URLPattern {
	return up
}

func NewURLPattern(urlStr string) *URLPattern {
	p := &URLPattern{urlStr: urlStr}
	u, err := url.Parse(urlStr)
	if err != nil {
		p.err = err
		return p
	}
	p.URL = u
	// p.Checker = NewURLChecker()
	p.Scope = u.Hostname()
	return p
}

// 在检查一个 URL 是否被允许访问时，URLChecker 会先检查该 URL 是否属于某个 scope，然后再根据具体的规则来判断是否允许访问。
func (uc *URLChecker) AddScope(scope string) *URLChecker {
	uc.Scope = scope
	return uc
}
func (uc *URLChecker) Close() error {
	if uc.Filter != nil {
		return uc.Filter.Close()
	}
	return nil
}
func (uc *URLChecker) DisableAutoInsert() *URLChecker {
	uc.AutoInsertDisabled = true
	return uc
}
func (uc *URLChecker) Insert(urlStr string) {
	if uc.Filter != nil {
		uc.Filter.Insert(urlStr, uc.TTL)
	}
}

func (uc *URLChecker) InsertWithTTL(urlStr string, ttl int64) {
	pattern := NewURLPattern(urlStr)
	pattern.TTL = ttl
	pattern.AutoInsertDisabled = true
	if pattern.err != nil {
		return
	}
}

func (uc *URLChecker) IsInserted(urlStr string, deleteExpired bool) bool {
	if uc.Filter == nil {
		return false
	}
	return uc.Filter.IsInserted(urlStr, false, 0)
}

func (uc *URLChecker) IsInsertedWithTTL(u string, includeSubdomains bool, now int64) bool {
	if uc.Filter == nil {
		return false
	}
	if uc.AutoInsertDisabled {
		return uc.Filter.IsInserted(u, includeSubdomains, uc.TTL)
	}

	uc.Insert(u)
	return false
}

// 创建一个新的URLChecker实例，该实例的作用域为给定的字符串。
func (*URLChecker) NewSubChecker(string) *URLChecker {
	return nil
}
func (c *URLChecker) Reset() error {
	// Reset all matchers

	// Reset AutoInsertDisabled and TTL
	c.AutoInsertDisabled = false
	c.TTL = 0
	return nil
}

func (uc *URLChecker) TargetStr(urlStr string) *URLPattern {
	urlPtn := &URLPattern{
		Checker: uc,
		urlStr:  urlStr,
	}

	//if uc.config != nil {
	//	urlPtn.Scope = uc.config.DefaultScope
	//	urlPtn.AutoInsertDisabled = uc.config.AutoInsertDisabled
	//	urlPtn.TTL = uc.config.DefaultTTL
	//}

	if parsedURL, err := url.Parse(urlStr); err == nil {
		urlPtn.URL = parsedURL
	} else {
		urlPtn.err = fmt.Errorf("failed to parse url string: %w", err)
	}

	return urlPtn
}

// 这个方法接受一个URL对象，返回一个URLPattern对象，其中URLPattern对象的Checker字段指向当前的URLChecker对象，URL字段指向传入的URL对象，其他字段来自于当前URLChecker对象的属性。
func (uc *URLChecker) TargetURL(u *url.URL) *URLPattern {
	return &URLPattern{
		Checker:            uc,
		urlStr:             u.String(),
		URL:                u,
		Scope:              uc.Scope,
		AutoInsertDisabled: uc.AutoInsertDisabled,
		TTL:                uc.TTL,
	}
}

// 这个方法接收一个int64类型的ttl参数，将URLChecker的TTL属性设置为这个值，并返回*URLChecker类型的对象。这个方法允许在检查URL之前设置TTL值，以覆盖默认值。
func (uc *URLChecker) WithTTL(ttl int64) *URLChecker {
	uc.TTL = ttl
	return uc
}

func NewURLChecker(config *URLCheckerConfig, filter filter.Filter) *URLChecker {
	uc := &URLChecker{}
	uc.Filter = filter
	uc.config = config

	uc.SchemeAllowedMatcher = matcher.NewKeyMatcher()
	uc.SchemeAllowedMatcher.Add(config.SchemeAllowed)

	uc.SchemeDisallowedMatcher = matcher.NewKeyMatcher()
	uc.SchemeDisallowedMatcher.Add(config.SchemeDisallowed)

	uc.HostnameAllowedMatcher = matcher.NewHostsMatcher()
	uc.HostnameAllowedMatcher.Add(config.HostnameAllowed)

	uc.HostnameDisallowedMatcher = matcher.NewHostsMatcher()
	uc.HostnameDisallowedMatcher.Add(config.HostnameDisallowed)

	uc.TCPPortAllowedMatcher = matcher.NewPortMatcher()
	uc.TCPPortAllowedMatcher.Add(config.TCPPortAllowed)
	uc.TCPPortDisallowedMatcher = matcher.NewPortMatcher()
	uc.TCPPortDisallowedMatcher.Add(config.TCPPortDisallowed)

	uc.PathAllowedMatcher = matcher.NewGlobMatcher()
	uc.PathAllowedMatcher.Add(config.PathAllowed)

	uc.PathDisallowedMatcher = matcher.NewGlobMatcher()
	uc.PathDisallowedMatcher.Add(config.PathDisallowed)

	uc.PathSuffixAllowedMatcher = matcher.NewKeyMatcher()
	uc.PathSuffixDisallowedMatcher = matcher.NewKeyMatcher()

	uc.QueryKeyAllowedMatcher = matcher.NewGlobMatcher()
	uc.QueryKeyAllowedMatcher.Add(config.QueryKeyAllowed)
	uc.QueryKeyDisallowedMatcher = matcher.NewGlobMatcher()
	uc.QueryKeyDisallowedMatcher.Add(config.QueryKeyDisallowed)

	uc.QueryRawAllowedMatcher = matcher.NewGlobMatcher()
	uc.QueryRawDisallowedMatcher = matcher.NewGlobMatcher()

	uc.FragmentAllowedMatcher = matcher.NewGlobMatcher()
	uc.FragmentAllowedMatcher.Add(config.FragmentAllowed)
	uc.FragmentDisallowedMatcher = matcher.NewGlobMatcher()
	uc.FragmentDisallowedMatcher.Add(config.FragmentDisallowed)

	uc.URLRegexAllowedMatcher = matcher.NewRegexpMatcher()
	uc.URLRegexDisallowedMatcher = matcher.NewRegexpMatcher()

	uc.URLGlobAllowedMatcher = matcher.NewGlobMatcher()
	uc.URLGlobDisallowedMatcher = matcher.NewGlobMatcher()
	return uc
}
