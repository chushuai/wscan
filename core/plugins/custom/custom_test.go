/**
2 * @Author: shaochuyu
3 * @Date: 12/9/23
4 */

package custom

import (
	"fmt"
	"testing"
)

func TestTemplate(t *testing.T) {
	if yss, err := LoadSingleTemplate("./tmpl/sample.yml", nil); err != nil {
		t.Error(err)
	} else {
		for _, ys := range yss {
			fmt.Println(ys.YamlScript)
		}
	}
}
