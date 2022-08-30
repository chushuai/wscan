/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package checker

import "wscan/core/utils/checker/matcher"

type RequestChecker struct {
	*URLChecker
	MethodAllowedMatcher     *matcher.KeyMatcher
	MethodDisallowedMatcher  *matcher.KeyMatcher
	PostKeyAllowedMatcher    *matcher.GlobMatcher
	PostKeyDisallowedMatcher *matcher.GlobMatcher
}

type RequestCheckerConfig struct {
	URLCheckerConfig  `json:",inline" yaml:",inline"`
	MethodAllowed     []string `json:"-" yaml:"-"`
	MethodDisallowed  []string `json:"-" yaml:"-"`
	PostKeyAllowed    []string `json:"post_key_allowed" yaml:"post_key_allowed" #:"允许访问的 Post Body 中的参数, 支持的格式如: test、*test*"`
	PostKeyDisallowed []string `json:"post_key_disallowed" yaml:"post_key_disallowed" #:"不允许访问的 Post Body 中的参数, 支持的格式如: test、*test*"`
}
