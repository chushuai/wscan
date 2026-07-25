/**
2 * @Author: shaochuyu
3 * @Date: 6/27/23
4 */

package prometheus

import (
	"github.com/google/cel-go/cel"
	"gopkg.in/yaml.v3"
)

type KVAst struct {
	Ast *cel.Ast
	Key string
}

type Rule2 struct {
	// RawRequest yaml.Node `yaml:"request,omitempty"`
	Request RuleRequest `yaml:"request,omitempty"`
	// Request     transport.Request `yaml:"-"`
	Expression  string    `yaml:"expression"`
	ExpCache    *cel.Ast  `yaml:"-"`
	Output      yaml.Node `yaml:"output,omitempty"`
	OutputCache []*KVAst  `yaml:"-"`
}

type Payloads2 struct {
	Continue      bool                 `yaml:"break,omitempty"`
	Payloads      map[string]yaml.Node `yaml:"payloads"`
	PayloadsCache map[string][]*KVAst  `yaml:"-"`
}

type Script struct {
	TransportName string `yaml:"transport"`
	// Transport     transport.Transport     `yaml:"-"`
	Set        yaml.Node         `yaml:"set,omitempty"`
	SetCache   []*KVAst          `yaml:"-"`
	Payloads   *Payloads2        `yaml:"payloads,omitempty"`
	Rules      map[string]*Rule2 `yaml:"rules"`
	Expression string            `yaml:"expression"`
	ExpCache   *cel.Ast          `yaml:"-"`
}

type SetVariable struct {
	Key   string
	Value any
}

//func (*Rule) GetFunctionRef(string) *functions.FunctionRef{
//	return nil
//}

func (*Rule2) InitOutput([]SetVariable, bool) error {
	return nil
}

/*



*script.Payloads

*script.Rule
func (*script.Rule) GetFunctionRef(string) *functions.FunctionRef
func (*script.Rule) InitOutput([]script.SetVariable, bool) error

*script.Script
func (*script.Script) InitPayloads(map[string][]script.SetVariable, bool, bool) error
func (*script.Script) InitSet([]script.SetVariable, bool) error
func (*script.Script) toYamlNode()
*/
