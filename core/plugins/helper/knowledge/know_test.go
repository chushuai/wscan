/**
2 * @Author: shaochuyu
3 * @Date: 12/10/22
4 */

package knowledge

import (
	"fmt"
	"testing"
	"wscan/core/http"
)

// [default:know.go:138] new knowledge for http://testphp.vulnweb.com, is_php: fingerprint_found

func TestKnowledgeDB(t *testing.T) {
	fmt.Println("---------")
	flow := http.Flow{}
	kb := NewKnowledgeDB(nil)

	kb.SaveFingerprint(&flow, "is_php")
	kb.SaveFingerprint(&flow, "is_asp")
	fmt.Println(kb)
}
