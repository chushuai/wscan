/**
2 * @Author: shaochuyu
3 * @Date: 3/27/24
4 */

package matcher

import (
	"fmt"
	"testing"
)

func TestNewHostsMatcher(t *testing.T) {
	hm := NewHostsMatcher()
	fmt.Println(hm.IsEmpty())
	hm.Add([]string{"www.baidu.com"})
	fmt.Println(hm.IsEmpty())
}
