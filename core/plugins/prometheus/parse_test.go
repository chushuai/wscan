/**
2 * @Author: shaochuyu
3 * @Date: 12/9/23
4 */

package prometheus

import (
	"fmt"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/parser"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"os"
	"testing"
	"wscan/core/model"
	"wscan/core/plugins/helper"
	logger "wscan/core/utils/log"
)

func TestParse(t *testing.T) {
	c := helper.NewEnvOption()

	globalEnv, err := helper.NewEnv(c)
	if err != nil {
		logger.Error("Environment creation error")
	}
	expression := "response.status == 200"
	variableMap := make(map[string]any)
	protoResponse := &model.Response{}
	variableMap["response"] = protoResponse
	out, err := helper.Evaluate(globalEnv, expression, variableMap)
	if err != nil {
		wrappedErr := errors.Wrapf(err, "Evalaute expression error: %s", expression)
		logger.Error(wrappedErr)
		return
	}
	fmt.Println(out)
}

func TestScript(t *testing.T) {
	poc := &Script{}
	poc2 := &Poc{}
	f, err := os.Open("./pocs/yamlpoc/poc-yaml-ssrf-reverse.yml")
	if err != nil {
		t.Error(err)
	}
	defer f.Close()
	if err != nil {
		t.Error(err)
	}
	err = yaml.NewDecoder(f).Decode(poc)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(poc)
	fmt.Println("------------------")
	f.Seek(0, 0)
	err = yaml.NewDecoder(f).Decode(poc2)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(poc2)
}

func TestParser(t *testing.T) {
	pr, _ := parser.NewParser()
	parsed, commonErr := pr.Parse(common.NewTextSource("1+1"))
	if len(commonErr.GetErrors()) != 0 {
		t.Error(commonErr.ToDisplayString())
	}
	fmt.Println(parsed)
}

func TestCompile(t *testing.T) {
	c := helper.NewEnvOption()

	env, err := helper.NewEnv(c)
	if err != nil {
		logger.Error("Environment creation error")
	}
	ast, iss := env.Compile(`"var_dump("+md5("494230670")+".md5())"`)
	err = iss.Err()
	if err != nil {
		t.Error(err)
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Error(err)
	}
	variableMap := make(map[string]any)
	out, _, _ := prg.Eval(variableMap)
	fmt.Println(out)
}
