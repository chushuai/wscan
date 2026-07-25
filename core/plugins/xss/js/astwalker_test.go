/**
2 * @Author: shaochuyu
3 * @Date: 4/20/24
4 */

package js

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/robertkrimen/otto/ast"
	"github.com/robertkrimen/otto/parser"
	"github.com/thoas/go-funk"
	"strings"
	"testing"
)

const code = `
// Sample xyzzy example
(function(){
	2021-12-23+"asdfasdf"

	0aasd111

	if (3.14159 > 0) {
		console.log("Hello, World.");
		return;
	}

	document.cookie.set("asdfasdfasdf" + "asdfasdfasdf")

	var xyzzy = NaN;
	console.log("Nothing happens.");
	return xyzzy;
})();
`

func TestBasicJavaScriptASTWalker(t *testing.T) {
	results, err := BasicJavaScriptASTWalker(code)
	if err != nil {
		panic(err)
	}
	spew.Dump(results)
}

func TestJS_AST(t *testing.T) {
	astInstance, _ := parser.ParseFile(nil, "", code, 0)

	w := NewJavaScriptWalker()
	var ints []int64
	w.OnInt64Literal = func(i int64) {
		println(i)
		ints = append(ints, i)
	}
	var strs []string
	w.OnStringLiteral = func(i string) {
		strs = append(strs, i)
	}
	var ids []string
	w.OnIdentifier = func(i string, n ast.Node) {
		ids = append(ids, i)
	}

	ast.Walk(w, astInstance)
	var res = funk.Map(ints, func(i int64) string {
		return fmt.Sprint(i)
	}).([]string)
	println(strings.Join(res, "-"))
	println(strings.Join(strs, "|"))
	println(strings.Join(ids, "|"))

	//for _, statement := range astInstance.Body {
	//	switch ret := statement.(type) {
	//	case *ast.ExpressionStatement:
	//		visitExpression(ret.Expression)
	//	}
	//}
}
