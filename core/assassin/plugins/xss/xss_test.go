/**
2 * @Author: shaochuyu
3 * @Date: 11/25/22
4 */

package xss

import (
	"encoding/json"
	"fmt"
	dalfox "github.com/hahwul/dalfox/v2/lib"
	"testing"
)

func PrintJson(data interface{}) {
	if ret, err := json.Marshal(data); err == nil {
		fmt.Println(string(ret))
	}
}

func TestXSS(t *testing.T) {
	opt := dalfox.Options{}
	result, err := dalfox.NewScan(dalfox.Target{
		URL:     "http://testphp.vulnweb.com/listproducts.php?artist=123&asdf=ff&cat=123%22%3E%3Csvg%2Fclass%3D%22dalfox%22onLoad%3Dalert%2845%29%3E",
		Method:  "GET",
		Options: opt,
	})
	if err != nil {
		fmt.Println(err)
	} else {
		PrintJson(result)
	}
}
