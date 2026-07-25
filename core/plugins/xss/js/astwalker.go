/**
2 * @Author: shaochuyu
3 * @Date: 4/20/24
4 */

package js

import (
	"errors"
	"fmt"
	"github.com/robertkrimen/otto/ast"
	"github.com/robertkrimen/otto/parser"
	"wscan/core/utils/log"
)

type ASTWalkerResult struct {
	StringLiteral  []string
	Int64Literal   []int64
	Float64Literal []float64
	Identifies     []string
	BadSyntax      []string
}

func BasicJavaScriptASTWalker(code string) (*ASTWalkerResult, error) {
	walker := NewJavaScriptWalker()
	walker.code = code
	var results = &ASTWalkerResult{}
	walker.OnStringLiteral = func(i string) {
		results.StringLiteral = append(results.StringLiteral, i)
	}
	walker.OnInt64Literal = func(i int64) {
		results.Int64Literal = append(results.Int64Literal, i)
	}
	walker.OnFloat64Literal = func(i float64) {
		results.Float64Literal = append(results.Float64Literal, i)
	}
	walker.OnIdentifier = func(i string, n ast.Node) {
		results.Identifies = append(results.Identifies, i)
	}
	walker.OnSyntaxError = func(i string, lastNode ast.Node) {
		results.BadSyntax = append(results.BadSyntax, i)
	}
	astProgram, _ := parser.ParseFile(nil, "", code, 0)
	if astProgram == nil {
		return nil, errors.New("ast program empty")
	}
	ast.Walk(walker, astProgram)
	return results, nil
}

type walker struct {
	code     string
	lastNode ast.Node
	handlers []func(n ast.Node)

	OnInt64Literal   func(i int64)
	OnFloat64Literal func(i float64)
	OnStringLiteral  func(i string)
	OnIdentifier     func(i string, lastNode ast.Node)
	OnSyntaxError    func(i string, lastNode ast.Node)
}

func (w *walker) init() {
	if w.OnStringLiteral == nil {
		w.OnStringLiteral = func(i string) {

		}
	}

	if w.OnInt64Literal == nil {
		w.OnInt64Literal = func(i int64) {

		}
	}

	if w.OnFloat64Literal == nil {
		w.OnFloat64Literal = func(i float64) {

		}
	}

	if w.OnIdentifier == nil {
		w.OnIdentifier = func(i string, N ast.Node) {

		}
	}

	if w.OnSyntaxError == nil {
		w.OnSyntaxError = func(i string, lastNode ast.Node) {

		}
	}
}

func NewJavaScriptWalker(handlers ...func(ast.Node)) *walker {
	w := &walker{handlers: handlers}
	w.init()
	return w
}

func (w *walker) Enter(n ast.Node) ast.Visitor {
	defer func() {
		w.lastNode = n

		if err := recover(); err != nil {
			log.Warnf("javascript ast walk error: %s", err)
		}
	}()

	for _, handler := range w.handlers {
		handler(n)
	}

	switch ret := n.(type) {
	case *ast.BadStatement:
		if ret.From < ret.To && (len(w.code)-1) >= int(ret.From) {
			w.OnSyntaxError(w.code[ret.From:ret.To], ret)
		}
	case *ast.BadExpression:
		if ret.From < ret.To && (len(w.code)-1) >= int(ret.From) {
			if len(w.code) > int(ret.To) {
				w.OnSyntaxError(w.code[ret.From:ret.To], ret)
			} else {
				w.OnSyntaxError(w.code[ret.From:], ret)
			}
		}
	case *ast.StringLiteral:
		w.OnStringLiteral(ret.Value)
	case *ast.NumberLiteral:
		switch number := ret.Value.(type) {
		case float64:
			w.OnFloat64Literal(number)
		case int64:
			w.OnInt64Literal(number)
		default:
			log.Errorf("cannot supported: %v", ret)
		}
	case *ast.Identifier:
		if ret == nil {
			return w
		}
		w.OnIdentifier(ret.Name, w.lastNode)
	default:
		fmt.Println(ret)
	}
	return w
}

func (w *walker) Exit(n ast.Node) {

}
