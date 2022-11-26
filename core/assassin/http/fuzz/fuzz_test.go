/**
2 * @Author: shaochuyu
3 * @Date: 11/26/22
4 */

package fuzz

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestParseFormQuery(t *testing.T) {
	req, _ := http.NewRequest("POST", "http://www.google.com/search?q=foo&q=bar&both=x&prio=1&orphan=nope&empty=not",
		strings.NewReader("z=post&both=y&prio=2&=nokey&orphan&empty=&"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")

	if q := req.FormValue("q"); q != "foo" {
		t.Errorf(`req.FormValue("q") = %q, want "foo"`, q)
	}
	if z := req.FormValue("z"); z != "post" {
		t.Errorf(`req.FormValue("z") = %q, want "post"`, z)
	}
	if bq, found := req.PostForm["q"]; found {
		t.Errorf(`req.PostForm["q"] = %q, want no entry in map`, bq)
	}
	if bz := req.PostFormValue("z"); bz != "post" {
		t.Errorf(`req.PostFormValue("z") = %q, want "post"`, bz)
	}
	if qs := req.Form["q"]; !reflect.DeepEqual(qs, []string{"foo", "bar"}) {
		t.Errorf(`req.Form["q"] = %q, want ["foo", "bar"]`, qs)
	}
	if both := req.Form["both"]; !reflect.DeepEqual(both, []string{"y", "x"}) {
		t.Errorf(`req.Form["both"] = %q, want ["y", "x"]`, both)
	}
	if prio := req.FormValue("prio"); prio != "2" {
		t.Errorf(`req.FormValue("prio") = %q, want "2" (from body)`, prio)
	}
	if orphan := req.Form["orphan"]; !reflect.DeepEqual(orphan, []string{"", "nope"}) {
		t.Errorf(`req.FormValue("orphan") = %q, want "" (from body)`, orphan)
	}
	if empty := req.Form["empty"]; !reflect.DeepEqual(empty, []string{"", "not"}) {
		t.Errorf(`req.FormValue("empty") = %q, want "" (from body)`, empty)
	}
	if nokey := req.Form[""]; !reflect.DeepEqual(nokey, []string{"nokey"}) {
		t.Errorf(`req.FormValue("nokey") = %q, want "nokey" (from body)`, nokey)
	}
}

func TestFuzz(t *testing.T) {
	tests := []struct {
		raw     string
		payload string
		field   string
		want    string
	}{{raw: "z=post&both=y&prio=2&c=nokey&orphan&empty=&", payload: "fuzzdata", field: "z", want: "both=y&c=nokey&empty=&orphan=&prio=2&z=fuzzdata"},
		{raw: "z=post&both=y&prio=2&c=nokey&orphan&empty=&", payload: "fuzzdata", field: "empty", want: "both=y&c=nokey&orphan=&prio=2&z=post&empty=fuzzdata"}}
	for _, test := range tests {
		qs, err := url.ParseQuery(test.raw)
		if err != nil {
			t.Error(err)
		}
		var value string
		if vs, ok := qs[test.field]; ok {
			if len(vs) == 0 {
				value = ""
			} else {
				value = vs[0]
			}
			qs.Del(test.field)
		} else {

		}
		value = test.payload
		got := qs.Encode()
		if got != "" {
			got += "&"
		}
		// 把`field`放在最后，供人工验证时判断
		got += fmt.Sprintf("%v=%v", test.field, value)
		if got != test.want {
			t.Errorf("want=%s, got=%s", test.want, got)
		}
	}

}
