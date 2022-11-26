/**
2 * @Author: shaochuyu
3 * @Date: 11/27/22
4 */

package fuzz

import (
	"encoding/json"
	"fmt"
	"testing"
	"wscan/core/assassin/http/fuzz/model"
)

func TestModel(t *testing.T) {
	o := model.Options{}
	if data, err := json.Marshal(o); err != nil {
		t.Error(err)
	} else {
		fmt.Println(string(data))
	}
}
