/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package jsonp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type JSONPParser struct {
	wantedFuncs   []string
	maxLevel      int
	sensitiveKeys map[string]bool
}

func (*JSONPParser) Parse() {

}
func (*JSONPParser) recursiveExp() {

}
func (*JSONPParser) recursiveObj() {

}

type ParseResult struct {
	vulnerable    bool
	MatchedStr    string
	MatchedStrKey string
	Err           error
}

func jsonpLoad(jsonp string) string {
	re := regexp.MustCompile(`^[^(]*?\((.*)\)[^)]*$`)
	match := re.FindStringSubmatch(jsonp)
	if match == nil {
		return ""
	}
	jsonText := match[1]
	if jsonText == "" {
		return ""
	}
	var arr interface{}
	if err := json.Unmarshal([]byte(jsonText), &arr); err != nil {
		return ""
	}
	return fmt.Sprintf("%v", arr)
}

func infoSearch(text string) map[string]interface{} {
	// 在这里定义 sensitive_bankcard、sensitive_idcard、sensitive_phone、sensitive_email 函数
	// ...

	sensitiveParams := []func(string) map[string]interface{}{} // []func(string) map[string]interface{}{sensitive_bankcard, sensitive_idcard, sensitive_phone, sensitive_email}
	sensitiveList := []string{"username", "memberid", "nickname", "loginid", "mobilephone", "userid", "passportid",
		"profile", "loginname", "loginid",
		"email", "realname", "birthday", "sex", "ip"}

	for _, sensitiveFunc := range sensitiveParams {
		ret := sensitiveFunc(text)
		if ret != nil {
			return ret
		}
	}
	for _, item := range sensitiveList {
		if strings.ToLower(item) == strings.ToLower(text) {
			return map[string]interface{}{"type": "keyword", "content": item}
		}
	}
	return nil
}

func checkSensitiveContent(resp string) map[string]interface{} {
	script := strings.TrimSpace(resp)
	if script == "" {
		return nil
	}
	if script[0] == '{' {
		script = "d=" + script
	}
	// 在这里定义 parse、analyseLiteral 函数
	// ...

	//doc, err := goquery.NewDocumentFromReader(strings.NewReader(script))
	//if err != nil {
	//	return nil
	//}
	//// 使用 goquery 解析文档，获取节点信息
	//// ...
	//
	//literals := analyseLiteral(nodes)
	//result := make(map[string]interface{})
	//for _, item := range literals {
	//	v := w.infoSearch(item)
	//	if v != nil {
	//		result[item] = v["content"]
	//	}
	//}
	//return result
	return nil
}
