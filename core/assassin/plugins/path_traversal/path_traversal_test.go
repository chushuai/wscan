/**
2 * @Author: shaochuyu
3 * @Date: 5/7/2022 11:30
4 */

package path_traversal

import (
	"fmt"
	"testing"
)

func TestFileIncludeRules(t *testing.T) {
	for _, rule := range pathTraversalRules {
		fmt.Println(rule)
	}
}
