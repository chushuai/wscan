package jsonpath

import (
	"encoding/json"
	"github.com/davecgh/go-spew/spew"
	"reflect"
	"strings"
	"testing"
	"wscan/core/utils"
)

var goessner = []byte(`{
    "store": {
        "book": [
            {
                "category": "reference",
                "author": "Nigel Rees",
                "title": "Sayings of the Century",
                "price": 8.95
            },
            {
                "category": "fiction",
                "author": "Evelyn Waugh",
                "title": "Sword of Honour",
                "price": 12.99
            },
            {
                "category": "fiction",
                "author": "Herman Melville",
                "title": "Moby Dick",
                "isbn": "0-553-21311-3",
                "price": 8.99
            },
            {
                "category": "fiction",
                "author": "J. R. R. Tolkien",
                "title": "The Lord of the Rings",
                "isbn": "0-395-19395-8",
                "price": 22.99
            }
        ],
        "bicycle": {
            "color": "red",
            "price": 19.95
        }
    },
    "expensive": 10
}`)

var sample = map[string]any{
	"A": []any{
		"string",
		23.3,
		3,
		true,
		false,
		nil,
	},
	"B": "value",
	"C": 3.14,
	"D": map[string]any{
		"C": 3.1415,
		"V": []any{
			"string2a",
			"string2b",
			map[string]any{
				"C": 3.141592,
			},
		},
	},
	"E": map[string]any{
		"A": []any{"string3"},
		"D": map[string]any{
			"V": map[string]any{
				"C": 3.14159265,
			},
		},
	},
	"F": map[string]any{
		"V": []any{
			"string4a",
			"string4b",
			map[string]any{
				"CC": 3.1415926535,
			},
			map[string]any{
				"CC": "hello",
			},
			[]any{
				"string5a",
				"string5b",
			},
			[]any{
				"string6a",
				"string6b",
			},
		},
	},
}

func TestGossner(t *testing.T) {
	var data any
	json.Unmarshal(goessner, &data)

	tests := map[string]any{
		"$.store.book[*].author": []any{"Nigel Rees", "Evelyn Waugh", "Herman Melville", "J. R. R. Tolkien"},
		"$..author":              []any{"Nigel Rees", "Evelyn Waugh", "Herman Melville", "J. R. R. Tolkien"},
	}
	assert(t, data, tests)
}

func TestReplace(t *testing.T) {
	t.Run("replace", func(t *testing.T) {
		assertReplace(t, sample, []string{
			`$.A[0]`,
			`$["A"][0]`,
			`$.A`,
			`$.A[*]`,
			`$.A.*`,
			`$.A.*.a`,
			`$.A[1,4,2]`,
			`$.F.V[4:6]`,
			`$["B","C"]`,
			`$.A[::2]`,
			`$.A[::-1]`,
			`$.F.V[4:5][0,1]`,
			`$.F.V[4:6][0,1]`,
			`$.F.V[4,5][0:2]`,
			`$.A[1,4,2]`,
			`$["C","B"]`,
			`$.A[1:4]`,
			`$.A[-2:]`,
			`$.A[:-1]`,
			`$.F.V[4:6][1]`,
			`$[A][0]`,
			`$["A"][0]`,
			`$[B,C]`,
			`$["B","C"]`,
			`$..A..*`,
			`$..A[0,1]`,
			`$.*.V[2].*`,
			`$.*.V[2:3].*`,
			`$.*.V[2:4].*`,
			`$.D.*..C`,
			`$..A`,
			`$..V[2].C`,
			`$..V[*].*`,
			`$.*.D.V.C`,
			`$.*.D..C`,
			`$.*.D.V..*`,
			`$.A.*`,
			`$..A[0]`,
			`$..V[2,3].CC`,
			`$.D.V..C`,
			`$.A..*`,
			`$.*.V[0:2]`,
			`$..V[*].C`,
			`$..V[2:4].CC`,
			`$.D.V.*.C`,
			`$..V..C`,
			`$.*.V..C`,
			`$.*.*.*.C`,
			`$.D.V..*`,
			`$.*.V[0]`,
			`$.*.V[0,1]`,
			`$.*.V[2].C`,
			`$..ZZ`,
			`$.D.V..*.C`,
			`$..["C"]`,
			`$..D..V..C`,
			`$.*.V[1]`,
			`$..[0]`,
			`$..C`,
		})
	})
}

func TestParsing(t *testing.T) {
	t.Run("pick", func(t *testing.T) {
		assert(t, sample, map[string]any{
			"$":         sample,
			"$.A[0]":    "string",
			`$["A"][0]`: "string",
			"$.A":       []any{"string", 23.3, 3, true, false, nil},
			"$.A[*]":    []any{"string", 23.3, 3, true, false, nil},
			"$.A.*":     []any{"string", 23.3, 3, true, false, nil},
			"$.A.*.a":   []any{},
		})
	})

	t.Run("slice", func(t *testing.T) {
		assert(t, sample, map[string]any{
			"$.A[1,4,2]":      []any{23.3, false, 3},
			`$["B","C"]`:      []any{"value", 3.14},
			`$["C","B"]`:      []any{3.14, "value"},
			"$.A[1:4]":        []any{23.3, 3, true},
			"$.A[::2]":        []any{"string", 3, false},
			"$.A[-2:]":        []any{false, nil},
			"$.A[:-1]":        []any{"string", 23.3, 3, true, false},
			"$.A[::-1]":       []any{nil, false, true, 3, 23.3, "string"},
			"$.F.V[4:5][0,1]": []any{"string5a", "string5b"},
			"$.F.V[4:6][1]":   []any{"string5b", "string6b"},
			"$.F.V[4:6][0,1]": []any{"string5a", "string5b", "string6a", "string6b"},
			"$.F.V[4,5][0:2]": []any{"string5a", "string5b", "string6a", "string6b"},
			"$.F.V[4:6]": []any{
				[]any{
					"string5a",
					"string5b",
				},
				[]any{
					"string6a",
					"string6b",
				},
			},
		})
	})

	t.Run("quote", func(t *testing.T) {
		assert(t, sample, map[string]any{
			`$[A][0]`:    "string",
			`$["A"][0]`:  "string",
			`$[B,C]`:     []any{"value", 3.14},
			`$["B","C"]`: []any{"value", 3.14},
		})
	})

	t.Run("search", func(t *testing.T) {
		assert(t, sample, map[string]any{
			"$..C":       []any{3.14, 3.1415, 3.141592, 3.14159265},
			`$..["C"]`:   []any{3.14, 3.1415, 3.141592, 3.14159265},
			"$.D.V..C":   []any{3.141592},
			"$.D.V.*.C":  []any{3.141592},
			"$.D.V..*.C": []any{3.141592},
			"$.D.*..C":   []any{3.141592},
			"$.*.V..C":   []any{3.141592},
			"$.*.D.V.C":  []any{3.14159265},
			"$.*.D..C":   []any{3.14159265},
			"$.*.D.V..*": []any{3.14159265},
			"$..D..V..C": []any{3.141592, 3.14159265},
			"$.*.*.*.C":  []any{3.141592, 3.14159265},
			"$..V..C":    []any{3.141592, 3.14159265},
			"$.D.V..*": []any{
				"string2a",
				"string2b",
				map[string]any{
					"C": 3.141592,
				},
				3.141592,
			},
			"$..A": []any{
				[]any{"string", 23.3, 3, true, false, nil},
				[]any{"string3"},
			},
			"$..A..*":      []any{"string", 23.3, 3, true, false, nil, "string3"},
			"$.A..*":       []any{"string", 23.3, 3, true, false, nil},
			"$.A.*":        []any{"string", 23.3, 3, true, false, nil},
			"$..A[0,1]":    []any{"string", 23.3},
			"$..A[0]":      []any{"string", "string3"},
			"$.*.V[0]":     []any{"string2a", "string4a"},
			"$.*.V[1]":     []any{"string2b", "string4b"},
			"$.*.V[0,1]":   []any{"string2a", "string2b", "string4a", "string4b"},
			"$.*.V[0:2]":   []any{"string2a", "string2b", "string4a", "string4b"},
			"$.*.V[2].C":   []any{3.141592},
			"$..V[2].C":    []any{3.141592},
			"$..V[*].C":    []any{3.141592},
			"$.*.V[2].*":   []any{3.141592, 3.1415926535},
			"$.*.V[2:3].*": []any{3.141592, 3.1415926535},
			"$.*.V[2:4].*": []any{3.141592, 3.1415926535, "hello"},
			"$..V[2,3].CC": []any{3.1415926535, "hello"},
			"$..V[2:4].CC": []any{3.1415926535, "hello"},
			"$..V[*].*": []any{
				3.141592,
				3.1415926535,
				"hello",
				"string5a",
				"string5b",
				"string6a",
				"string6b",
			},
			"$..[0]": []any{
				"string",
				"string2a",
				"string3",
				"string4a",
				"string5a",
				"string6a",
			},
			"$..ZZ": []any{},
		})
	})
}

func TestErrors(t *testing.T) {
	tests := map[string]string{
		".A":           "path must start with a '$'",
		"$.":           "expected JSON child identifier after '.'",
		"$.1":          "unexpected token .1",
		"$.A[]":        "expected at least one key, index or expression",
		`$["]`:         "bad string invalid syntax",
		`$[A][0`:       "unexpected end of path",
		"$.ZZZ":        "child 'ZZZ' not found in JSON object",
		"$.A*]":        "unexpected token *",
		"$.*V":         "unexpected token V",
		"$[B,C":        "unexpected end of path",
		"$.A[1,4.2]":   "unexpected token '.'",
		"$[C:B]":       "expected JSON array",
		"$.A[1:4:0:0]": "bad range syntax [start:end:step]",
		"$.A[:,]":      "unexpected token ','",
		"$..":          "cannot end with a scan '..'",
		"$..1":         "unexpected token '1' after deep search '..'",
	}
	assertError(t, sample, tests)
}

func TestFind(t *testing.T) {
	raw := utils.InterfaceToBytes("[{\"events\":[{\"event\":\"predefine_page_alive\",\"params\":\"{\\\"_staging_flag\\\":0,\\\"enter_from\\\":\\\"unauth_a\\\",\\\"user_id\\\":\\\"b0f7578fe2a0a0aa4f2aab029277b14c92a80657\\\",\\\"tenant_id\\\":\\\"0804c971357615c3ee16b47da7783c7cbaefeb08\\\",\\\"username\\\":\\\"7250011182621343745\\\",\\\"tenant_key\\\":\\\"736588c9260f175e\\\",\\\"saas_tenant_key\\\":\\\"saas_ccc1ff19-1e73-4aa1-869c-a32ce663e30b\\\",\\\"qpsd\\\":\\\"{}\\\",\\\"datetime\\\":1688378096543,\\\"os_name\\\":\\\"mac\\\",\\\"browser_name\\\":\\\"Chrome\\\",\\\"browser_version\\\":\\\"113\\\",\\\"timezone\\\":\\\"Asia/Shanghai\\\",\\\"scenario\\\":\\\"meego_web\\\",\\\"plaftorm_language\\\":\\\"zh\\\",\\\"enter_from_id\\\":\\\"649e88f2f818f2e92068a98b\\\",\\\"object_type\\\":\\\"story\\\",\\\"view_id\\\":\\\"HUNPcHr4g\\\",\\\"url_path\\\":\\\"/unauth_a/story/detail/11354996\\\",\\\"title\\\":\\\"飞书项目\\\",\\\"url\\\":\\\"https://project.feishu.cn/unauth_a/story/detail/11354996?parentUrl=%2Funauth_a%2FstoryView%2F0NrhAHrVg\\\",\\\"duration\\\":60000,\\\"is_support_visibility_change\\\":1,\\\"startTime\\\":1688378410842,\\\"hidden\\\":\\\"visible\\\",\\\"leave\\\":false,\\\"event_index\\\":1688376115660}\",\"local_time_ms\":1688378471833,\"is_bav\":0,\"session_id\":\"6318e880-6f50-409d-a6e2-db7188b9f1b0\"}],\"user\":{\"user_unique_id\":\"7250386110593353216\",\"user_id\":\"7250011182621343745\",\"web_id\":\"7250386110593353216\"},\"header\":{\"app_id\":1880,\"os_name\":\"mac\",\"os_version\":\"10_15_7\",\"device_model\":\"Macintosh\",\"language\":\"zh-CN\",\"platform\":\"web\",\"sdk_version\":\"5.0.52_1\",\"sdk_lib\":\"js\",\"timezone\":8,\"tz_offset\":-28800,\"resolution\":\"3008x1692\",\"browser\":\"Chrome\",\"browser_version\":\"113.0.0.0\",\"referrer\":\"\",\"referrer_host\":\"\",\"width\":3008,\"height\":1692,\"screen_width\":3008,\"screen_height\":1692,\"tracer_data\":\"{\\\"$utm_from_url\\\":1}\",\"custom\":\"{\\\"username\\\":\\\"7250011182621343745\\\"}\"},\"local_time\":1688378471,\"verbose\":1}]")
	var i any
	err := json.Unmarshal(raw, &i)
	if err != nil {
		t.Errorf("unmarshal json failed: %s", err)
		t.FailNow()
	}
	jpath := "$.[0].local_time"
	result, err := Read(i, jpath)
	if err != nil {
		t.Errorf("read jsonpath failed: %s", err)
		t.FailNow()
	}
	spew.Dump(result)
}

func assert(t *testing.T, json any, tests map[string]any) {
	for path, expected := range tests {
		actual, err := Read(json, path)
		if err != nil {
			t.Error("failed:", path, err)
		} else if !reflect.DeepEqual(actual, expected) {
			t.Errorf("failed: mismatch for %s\nexpected: %+v\nactual: %+v", path, expected, actual)
		}
	}
}

func assertReplace(t *testing.T, obj map[string]any, tests []string) {
	expected := "HACK"
	for _, path := range tests {
		newSample, err := Replace(obj, path, expected)
		if err != nil {
			t.Error("failed:", path, err)
		}
		actual, err := Read(newSample, path)
		if err != nil {
			t.Error("failed:", path, err)
		}
		switch v := actual.(type) {
		case []any:
			for _, vv := range v {
				if vv != expected {
					t.Errorf("failed: mismatch for %s\nexpected: %+v\nactual: %+v", path, expected, actual)
				}
			}
		case map[string]any:
			for _, vv := range v {
				if vv != expected {
					t.Errorf("failed: mismatch for %s\nexpected: %+v\nactual: %+v", path, expected, actual)
				}
			}
		default:
			if !reflect.DeepEqual(actual, expected) {
				t.Errorf("failed: mismatch for %s\nexpected: %+v\nactual: %+v", path, expected, actual)
			}
		}
	}
}

func assertError(t *testing.T, json any, tests map[string]string) {
	for path, expectedError := range tests {
		_, err := Read(json, path)
		if err == nil {
			t.Error("path", path, "should fail with", expectedError)
		} else if !strings.Contains(err.Error(), expectedError) {
			t.Error("path", path, "shoud fail with ", expectedError, "but failed with:", err)
		}
	}
}
