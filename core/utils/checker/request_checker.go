/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package checker

import (
	"net/url"
	"sync"
	"wscan/core/assassin/http"
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
	// Checker *<nil>
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

func (rc *RequestChecker) Target(*http.Request) *ReqPattern {
	return nil
}

func (rc *RequestChecker) TargetStr(string) *URLPattern {
	return nil
}

func (rc *RequestChecker) TargetURL(*url.URL) *URLPattern {
	return nil
}

func (rc *RequestChecker) WithTTL(int64) *URLChecker {
	return nil
}

func NewRequestChecker() *RequestChecker {
	//__int64 __usercall gunkit_core_utils_checker_NewRequestChecker@<rax>(__int64 a1, __int64 a2, __int64 a3)
	//{
	//  __int64 v3; // rax
	//  __int64 result; // rax
	//  __int64 v5; // rax
	//  __int64 v6; // rdx
	//  __int64 *v7; // [rsp+8h] [rbp-60h]
	//  __int64 v8; // [rsp+20h] [rbp-48h]
	//  __int64 v9; // [rsp+20h] [rbp-48h]
	//  __int128 v10; // [rsp+20h] [rbp-48h]
	//  __int64 v11; // [rsp+20h] [rbp-48h]
	//  __int64 v12; // [rsp+30h] [rbp-38h]
	//  __int64 *v13; // [rsp+38h] [rbp-30h]
	//  __int64 v14; // [rsp+40h] [rbp-28h]
	//  __int64 v15; // [rsp+48h] [rbp-20h]
	//  __int64 v16; // [rsp+50h] [rbp-18h]
	//  __int64 v17; // [rsp+58h] [rbp-10h]
	//  __int64 *v18; // [rsp+70h] [rbp+8h]
	//
	//  v3 = a1;
	//  if ( !a1 )
	//    v3 = runtime_newobject((__int64)&unk_172A200);
	//  v18 = (__int64 *)v3;
	//  result = gunkit_core_utils_checker_NewURLChecker(v3, a2, a3);
	//  if ( !v8 )
	//  {
	//    v12 = result;
	//    v17 = runtime_newobject((__int64)"0");
	//    v16 = runtime_newobject((__int64)"0");
	//    v15 = runtime_newobject((__int64)"(");
	//    v14 = runtime_newobject((__int64)"(");
	//    v7 = (__int64 *)runtime_newobject((__int64)"(");
	//    v13 = v7;
	//    if ( dword_3197BF0 )
	//    {
	//      runtime_gcWriteBarrierCX();
	//      runtime_gcWriteBarrierDX();
	//      runtime_gcWriteBarrierCX();
	//      runtime_gcWriteBarrierCX();
	//      runtime_gcWriteBarrierCX();
	//      v5 = v6;
	//    }
	//    else
	//    {
	//      *v7 = v12;
	//      v5 = v17;
	//      v7[1] = v17;
	//      v7[2] = v16;
	//      v7[3] = v15;
	//      v7[4] = v14;
	//    }
	//    result = gunkit_core_utils_checker_matcher___ptr_KeyMatcher__Add(v5, v18[60], v18[61], v18[62]);
	//    if ( !result )
	//    {
	//      v9 = gunkit_core_utils_checker_matcher___ptr_KeyMatcher__Add(v13[2], v18[63], v18[64], v18[65]);
	//      result = v9;
	//      if ( !v9 )
	//      {
	//        gunkit_core_utils_checker_matcher___ptr_GlobMatcher__Add(v13[3], v18[66], v18[67], v18[68], 0LL);
	//        result = v10;
	//        if ( !(_QWORD)v10 )
	//        {
	//          gunkit_core_utils_checker_matcher___ptr_GlobMatcher__Add(v13[4], v18[69], v18[70], v18[71], v10);
	//          result = v11;
	//          if ( !v11 )
	//            return (__int64)v13;
	//        }
	//      }
	//    }
	//  }
	//  return result;
	//}
	return nil
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
