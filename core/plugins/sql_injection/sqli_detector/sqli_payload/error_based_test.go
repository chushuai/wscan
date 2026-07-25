/**
2 * @Author: shaochuyu
3 * @Date: 11/25/23
4 */

package sqli_payload

import (
	"fmt"
	"testing"
)

func TestGetPayloads(t *testing.T) {
	for _, payload := range GetPayloads() {
		fmt.Println(payload)
	}
}
