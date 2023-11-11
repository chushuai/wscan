/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package checker

import (
	"sync"
	"wscan/core/http"
	"wscan/core/utils/checker/filter"
	"wscan/core/utils/checker/matcher"
)

type RequestChecker struct {
	*URLChecker
	MethodAllowedMatcher     *matcher.KeyMatcher
	MethodDisallowedMatcher  *matcher.KeyMatcher
	PostKeyAllowedMatcher    *matcher.GlobMatcher
	PostKeyDisallowedMatcher *matcher.GlobMatcher
}

// 1.Vscan webscan 定义checker filter数据结构和接口
type RequestCheckerConfig struct {
	URLCheckerConfig  `json:",inline" yaml:",inline"`
	MethodAllowed     []string `json:"-" yaml:"-"`
	MethodDisallowed  []string `json:"-" yaml:"-"`
	PostKeyAllowed    []string `json:"post_key_allowed" yaml:"post_key_allowed" #:"允许访问的 Post Body 中的参数, 支持的格式如: test、*test*"`
	PostKeyDisallowed []string `json:"post_key_disallowed" yaml:"post_key_disallowed" #:"不允许访问的 Post Body 中的参数, 支持的格式如: test、*test*"`
}

type ReqPattern struct {
	*URLPattern
	Checker     *RequestChecker
	bodyKeys    []string
	hash        string
	doCacheOnce sync.Once
	Req         *http.Request
}

func (rc *RequestChecker) AddScope(string) *RequestChecker {
	return nil
}

func (rc *RequestChecker) Close() error {
	return nil
}

func (rc *RequestChecker) DisableAutoInsert() *URLChecker {
	return nil
}

func (rc *RequestChecker) Insert(string) {
	return
}

func (rc *RequestChecker) InsertWithTTL(string, int64) {

}

func (rc *RequestChecker) IsInserted(string, bool) bool {
	return false
}

func (rc *RequestChecker) IsInsertedWithTTL(string, bool, int64) bool {
	return false
}

func (rc *RequestChecker) NewSubChecker(string) *RequestChecker {
	return nil
}

func (rc *RequestChecker) Reset() error {
	return nil
}

func (rc *RequestChecker) Target(req *http.Request) *ReqPattern {
	return &ReqPattern{
		//*URLPattern
		Checker: rc,
		//bodyKeys    []string
		hash: "",
		Req:  req,
	}
}

func (rc *RequestChecker) TargetStr(string) *URLPattern {
	return nil
}

func (rc *RequestChecker) WithTTL(int64) *URLChecker {
	return nil
}

func NewRequestChecker(config *RequestCheckerConfig, filter filter.Filter) *RequestChecker {
	rc := &RequestChecker{}
	rc.URLChecker = NewURLChecker(&config.URLCheckerConfig, filter)
	rc.MethodAllowedMatcher = matcher.NewKeyMatcher()
	rc.MethodAllowedMatcher.Add(config.MethodAllowed)
	rc.MethodDisallowedMatcher = matcher.NewKeyMatcher()
	rc.MethodDisallowedMatcher.Add(config.MethodDisallowed)
	rc.PostKeyAllowedMatcher = matcher.NewGlobMatcher()
	rc.PostKeyAllowedMatcher.Add(config.PostKeyAllowed)
	rc.PostKeyDisallowedMatcher = matcher.NewGlobMatcher()
	rc.PostKeyDisallowedMatcher.Add(config.PostKeyDisallowed)
	return rc
}

//*checker.ReqPattern
func (*ReqPattern) AddScope(string) *ReqPattern {
	return nil
}

func (rp *ReqPattern) Bool() bool {
	return false
}

func (rp *ReqPattern) DisableAutoInsert() *ReqPattern {
	return nil
}

func (rp *ReqPattern) Error() error {
	return nil
}

func (rp *ReqPattern) Hash() string {
	return ""
}

func (rp *ReqPattern) IsAllowed() *ReqPattern {
	return nil

}

func (rp *ReqPattern) IsNewHostName() *URLPattern {
	return nil
}

func (rp *ReqPattern) IsNewHostPort() *URLPattern {
	return nil
}

func (rp *ReqPattern) IsNewScanTarget() *ReqPattern {
	return nil
}

func (rp *ReqPattern) IsNewURL() *URLPattern {
	return nil
}

func (rp *ReqPattern) IsNewWebsiteDir() *URLPattern {
	return nil
}

func (rp *ReqPattern) IsNewWebsitePath() *URLPattern {
	return nil
}

func (rp *ReqPattern) IsNewWebsiteQueryKey() *URLPattern {
	return nil
}

func (rp *ReqPattern) URLString() string {
	return ""
}

func (rp *ReqPattern) WithTTL(int64) *ReqPattern {
	return nil
}

func (rp *ReqPattern) doCache() {

}
