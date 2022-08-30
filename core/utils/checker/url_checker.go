/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package checker

import (
	"net/url"
	"wscan/core/utils/checker/filter"
	"wscan/core/utils/checker/matcher"
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
	err error
	//Checker *<nil>
	urlStr             string
	URL                *url.URL
	Scope              string
	AutoInsertDisabled bool
	TTL                int64
}

//type checker.overloadResolution struct {
//Reference *expr.Reference
//Type      *expr.Type
//}
//
