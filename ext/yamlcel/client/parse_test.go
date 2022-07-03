package client

import (
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/parser"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestShortestPath(t *testing.T) {
	cases := map[string][]string{
		"r1()":                             {"r1"},
		"r1() && r2() && r3() && r4()":     {"r1", "r2", "r3", "r4"},
		"r1() || r2()":                     {"r2"},
		"r1() || (r2() && r3())":           {"r1"},
		"(r1() && r2()) || (r2() && r4())": {"r2", "r4"},
		"r1() && (r2() || (r4() && r5()))": {"r1", "r2"},
	}
	yr := &Yarx{}
	assert := require.New(t)
	pr, _ := parser.NewParser()
	for test, expected := range cases {
		t.Log(test)
		parsed, commonErr := pr.Parse(common.NewTextSource(test))
		assert.Zero(len(commonErr.GetErrors()))
		var result []string
		result = yr.getShortestExprPath(parsed.GetExpr(), result)
		assert.Equal(expected, result)
	}
}

func TestParseExpression(t *testing.T) {
	assert := require.New(t)
	yr := &Yarx{}
	toTest := `
response.body.bcontains(b"ef775988943825d2871e1cfa75473ec") && 
response.status == 201 && 
"root:[x*]:0:0:".bmatches(response.body) && 
response.headers["location"] == "https://www.du1x3r12.com" && 
response.headers["Set-Cookie"].contains("new-cookie")`
	rule := NewMutationRule(newCelContext())
	assert.Nil(yr.parseExpr(toTest, rule))

	var fakeResp RespMetrics
	for _, fn := range rule.MutateFuncs {
		assert.Nil(fn(&fakeResp, rule.cel))
	}
	assert.Equal(rule.Status, 201)
	assert.Equal(fakeResp.header.Get("location"), "https://www.du1x3r12.com")
	assert.Equal(fakeResp.header.Get("Set-Cookie"), "new-cookie")
	s1 := make([]byte, 1, 10)
	s2 := make([]byte, 1, 4)
	assert.Equal(s1, s2)
	val := string(fakeResp.body) == "ef775988943825d2871e1cfa75473ecroot:*:0:0:" || string(fakeResp.body) == "ef775988943825d2871e1cfa75473ecroot:x:0:0:"
	assert.True(val)
}
