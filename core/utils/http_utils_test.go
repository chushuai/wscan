/**
2 * @Author: shaochuyu
3 * @Date: 12/12/23
4 */

package utils

import (
	"fmt"
	"testing"
)

func TestUrlJoinPath(t *testing.T) {
	fmt.Println(UrlJoinPath("http://baidu.com", "a/"))
	fmt.Println(UrlJoinPath("http://baidu.com/p/", "a/"))
	fmt.Println(UrlJoinPath("http://baidu.com/p/", "/a/"))
}
