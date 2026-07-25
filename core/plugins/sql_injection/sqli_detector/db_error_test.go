/**
2 * @Author: shaochuyu
3 * @Date: 11/25/23
4 */

package sqli_detector

import (
	"fmt"
	"testing"
)

func TestNewErrorRegexList(t *testing.T) {
	for _, er := range NewErrorRegexList() {
		fmt.Println(er.Dbms)
	}
}
