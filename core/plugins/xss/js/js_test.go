/**
2 * @Author: shaochuyu
3 * @Date: 4/14/24
4 */

package js

import (
	"fmt"
	"github.com/dop251/goja"
	"github.com/dop251/goja/ast"
	"strings"
	"testing"
)

type JsParseError struct {
	Expression string
	Message    string
}

func (e *JsParseError) Error() string {
	return fmt.Sprintf("%s: %s", e.Expression, e.Message)
}

type Comment struct {
	Type  string
	Value string
}

func isLineTerminator(ch rune) bool {
	return ch == 0x0A || ch == 0x0D || ch == 0x2028 || ch == 0x2029
}

func isWhiteSpace(ch rune) bool {
	return ch == 0x20 || (0x09 <= ch && ch <= 0x0D) || ch == 0xA0 || ch == 0x1680 || ch == 0x180E || (0x2000 <= ch && ch <= 0x200A) || ch == 0x202F || ch == 0x205F || ch == 0x3000 || ch == 0xFEFF
}

func skipMultiLineComment(index int, source string) (int, string) {
	start := index
	for index < len(source) {
		ch := rune(source[index])
		if isLineTerminator(ch) {
			index++
			continue
		} else if ch == '*' && index+1 < len(source) && rune(source[index+1]) == '/' {
			index += 2
			return index, source[start : index-2]
		}
		index++
	}
	return index, ""
}

func skipSingleLineComment(index int, source string) (int, string) {
	start := index
	for index < len(source) {
		ch := rune(source[index])
		if isLineTerminator(ch) {
			return index, source[start:index]
		}
		index++
	}
	return index, ""
}

// FindVariableReferences attempts to extract all the variable references from the
// provided script. It returns an error only if the script is unable to be parsed.
func FindVariableReferences(script string) ([]string, error) {
	program, err := goja.Parse("", script)
	if err != nil {
		return nil, err
	}
	var expressions []ast.Expression
	for _, s := range program.Body {
		expressions = append(expressions, parseStatements(s)...)
	}
	var out []string
	for _, e := range expressions {
		out = append(out, parseExpression(e)...)
	}
	return out, nil
}

func parseStatements(s ast.Statement) (out []ast.Expression) {
	switch s.(type) {
	case *ast.BlockStatement:
		for _, st := range s.(*ast.BlockStatement).List {
			out = append(out, parseStatements(st)...)
		}
	case *ast.ReturnStatement:
		out = append(out, s.(*ast.ReturnStatement).Argument)
	case *ast.VariableStatement:
		fmt.Println("============")
	case *ast.ExpressionStatement:
		out = append(out, s.(*ast.ExpressionStatement).Expression)
	case *ast.SwitchStatement:
		sws := s.(*ast.SwitchStatement)
		out = append(out, sws.Discriminant)
		for _, c := range sws.Body {
			out = append(out, c.Test)
			for _, st := range c.Consequent {
				out = append(out, parseStatements(st)...)
			}
		}
	case *ast.CaseStatement:
		cs := s.(*ast.CaseStatement)
		out = append(out, cs.Test)
		for _, st := range cs.Consequent {
			out = append(out, parseStatements(st)...)
		}
	case *ast.BranchStatement:
		bs := s.(*ast.CaseStatement)
		out = append(out, bs.Test)
		for _, st := range bs.Consequent {
			out = append(out, parseStatements(st)...)
		}
	case *ast.CatchStatement:
		cs := s.(*ast.CatchStatement)
		out = append(out, parseStatements(cs.Body)...)
	case *ast.WhileStatement:
		ws := s.(*ast.WhileStatement)
		out = append(out, ws.Test)
		out = append(out, parseStatements(ws.Body)...)
	case *ast.DoWhileStatement:
		ds := s.(*ast.DoWhileStatement)
		out = append(out, ds.Test)
		out = append(out, parseStatements(ds.Body)...)
	case *ast.ForInStatement:
		fi := s.(*ast.ForInStatement)
		out = append(out, fi.Source)
		fmt.Println("============")
		out = append(out, parseStatements(fi.Body)...)
	case *ast.ForOfStatement:
		fi := s.(*ast.ForOfStatement)
		out = append(out, fi.Source)
		fmt.Println("============")
		out = append(out, parseStatements(fi.Body)...)
	case *ast.ForStatement:
		fi := s.(*ast.ForStatement)
		fmt.Println("============")
		out = append(out, fi.Update)
		out = append(out, fi.Test)
		out = append(out, parseStatements(fi.Body)...)
	case *ast.IfStatement:
		ifs := s.(*ast.ForStatement)
		fmt.Println("============")
		out = append(out, ifs.Test)
		out = append(out, ifs.Update)
		out = append(out, parseStatements(ifs.Body)...)
	case *ast.LabelledStatement:
		ifs := s.(*ast.LabelledStatement)
		out = append(out, parseStatements(ifs.Statement)...)
	case *ast.ThrowStatement:
		ts := s.(*ast.ThrowStatement)
		out = append(out, ts.Argument)
	case *ast.TryStatement:
		ts := s.(*ast.TryStatement)
		out = append(out, parseStatements(ts.Body)...)
		out = append(out, parseStatements(ts.Finally)...)
		out = append(out, parseStatements(ts.Catch.Body)...)
	case *ast.WithStatement:
		ws := s.(*ast.WithStatement)
		out = append(out, ws.Object)
		out = append(out, parseStatements(ws.Body)...)
	}
	return
}

func parseExpression(e ast.Expression) (out []string) {
	switch e.(type) {
	case *ast.DotExpression:
		out = append(out, traverseDotExpression("", e))
	case *ast.CallExpression:
		ce := e.(*ast.CallExpression)
		out = append(out, parseExpression(ce.Callee)...)
		for _, a := range ce.ArgumentList {
			out = append(out, parseExpression(a)...)
		}
	case *ast.AssignExpression:
		ae := e.(*ast.AssignExpression)
		out = append(out, parseExpression(ae.Left)...)
		out = append(out, parseExpression(ae.Right)...)
	case *ast.BinaryExpression:
		be := e.(*ast.BinaryExpression)
		out = append(out, parseExpression(be.Left)...)
		out = append(out, parseExpression(be.Right)...)
	case *ast.BracketExpression:
		be := e.(*ast.BracketExpression)
		out = append(out, parseExpression(be.Left)...)
		out = append(out, parseExpression(be.Member)...)
	case *ast.ConditionalExpression:
		ce := e.(*ast.ConditionalExpression)
		out = append(out, parseExpression(ce.Test)...)
		out = append(out, parseExpression(ce.Consequent)...)
		out = append(out, parseExpression(ce.Alternate)...)
	case *ast.NewExpression:
		ne := e.(*ast.NewExpression)
		out = append(out, parseExpression(ne.Callee)...)
		for _, a := range ne.ArgumentList {
			out = append(out, parseExpression(a)...)
		}
	case *ast.SequenceExpression:
		se := e.(*ast.SequenceExpression)
		for _, a := range se.Sequence {
			out = append(out, parseExpression(a)...)
		}
	case *ast.UnaryExpression:
		ue := e.(*ast.UnaryExpression)
		out = append(out, parseExpression(ue.Operand)...)
	case *ast.ObjectLiteral:
		ol := e.(*ast.ObjectLiteral)
		for _, p := range ol.Value {
			//out = append(out, parseExpression(p.Key)...)
			// out = append(out, parseExpression(p.Value)...)
			fmt.Println(p)
		}
	case *ast.StringLiteral:
		sl := e.(*ast.StringLiteral)
		out = append(out, string(sl.Value))
	case *ast.FunctionLiteral:
		sl := e.(*ast.FunctionLiteral)
		for _, s := range parseStatements(sl.Body) {
			out = append(out, parseExpression(s)...)
		}
	}
	return
}

func traverseDotExpression(path string, expression ast.Expression) string {
	if d, ok := expression.(*ast.DotExpression); ok {
		key := string(d.Identifier.Name)
		if len(path) > 0 {
			key = strings.Join([]string{string(d.Identifier.Name), path}, ".")
		}
		return traverseDotExpression(key, d.Left)
	}
	if id, ok := expression.(*ast.Identifier); ok {
		return strings.Join([]string{string(id.Name), path}, ".")
	}
	return path
}

func TestA(t *testing.T) {
	program, err := goja.Parse(``, `  function exampleFunction() {
            var number = 42;
            var text = 'Hello, World!';
            var obj = { key: 'value' };
            var arr = [1, 2, 3];
            return [number, text, obj, arr];
        }`)
	if err != nil {
		return
	}
	var expressions []ast.Expression
	for _, s := range program.Body {
		expressions = append(expressions, parseStatements(s)...)
	}
	var out []string
	for _, e := range expressions {
		out = append(out, parseExpression(e)...)
	}
	return
}
