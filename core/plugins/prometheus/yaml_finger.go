/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package prometheus

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/plugins/helper"
	"wscan/core/utils"

	"github.com/google/cel-go/checker/decls"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	//"wscan/core/plugins/prometheus/gamma/requests"
	logger "wscan/core/utils/log"
)

type YamlFinger struct {
	*YamlScript
	poc     *Poc
	init    func(context.Context, *base.Apollo) // transport.Target
	pocPath string
}

func (YamlFinger) Dump() ([]byte, error) {
	return nil, nil
}

func (YamlFinger) Init(bool) error {
	return nil
}
func (YamlFinger) MarshalYAML() (any, error) {
	return nil, nil
}

func (YamlFinger) compileNode() {

}
func (YamlFinger) compilePayloads() {

}
func (YamlFinger) run() {

}

func (y YamlFinger) Run(ctx context.Context, ab *base.Apollo) error {
	var (
		request       *http.Request
		oProtoRequest *model.Request
		protoRequest  *model.Request  //  保存请求报文
		protoResponse *model.Response // 保存响应报文
		variableMap   = make(map[string]any)
		requestFunc   helper.RequestFuncType
		snapShot      []any
	)

	flows := []*http.Flow{}
	poc := y.poc

	flow := ab.GetTargetFlow()
	logger.Infof("Running [%s] %s", y.poc.Name, flow.Request.URL().String())
	addr := flow.Request.URL().String()
	isVul := false
	// 异常处理
	defer func() {
		logger.Infof("END Running [%s] %s", y.poc.Name, flow.Request.URL().String())
		if r := recover(); r != nil {
			stackBuf := make([]byte, 4096)
			stackSize := runtime.Stack(stackBuf, false)
			stackTrace := string(stackBuf[:stackSize])
			logger.Errorf("Run Wscan Poc[%s] error %s", poc.Name, stackTrace)
			isVul = false
		}
	}()
	// 回收
	defer func() {
		for _, v := range variableMap {
			switch value := v.(type) {
			case *model.Reverse:
				helper.PutReverse(value)
			default:
			}
		}
	}()

	// 设置原始请求变量
	oProtoRequest, _ = helper.ConvertHttpRequestToModelRequest(flow.Request)
	variableMap["request"] = oProtoRequest

	// 判断transport，如果不合法则跳过
	transport := poc.Transport
	if transport == "tcp" || transport == "udp" {
		// 暂时不支持TCP/UDP请求
		return nil
	}

	// 初始化cel-go环境，并在函数返回时回收
	c := helper.NewEnvOption()
	defer helper.PutCustomLib(c)

	globalEnv, err := helper.NewEnv(c)
	if err != nil {
		logger.Error("Environment creation error")
		return err
	}

	// 定义渲染函数
	render := func(v string) string {
		for k1, v1 := range variableMap {
			_, isMap := v1.(map[string]string)
			if isMap {
				continue
			}
			v1Value := fmt.Sprintf("%v", v1)
			t := "{{" + k1 + "}}"
			if !strings.Contains(v, t) {
				continue
			}
			v = strings.ReplaceAll(v, t, v1Value)
		}
		return v
	}
	// 刷新环境
	ReCreateEnv := func(c *helper.CustomLib) (*helper.Env, error) {
		env, err := helper.NewEnv(c)
		if err != nil {
			return nil, err
		}
		return env, nil
	}

	// 定义evaluateUpdateVariableMap
	evaluateUpdateVariableMap := func(set yaml.MapSlice) error {
		for _, item := range set {
			k, expression := item.Key.(string), item.Value.(string)

			out, err := helper.Evaluate(globalEnv, expression, variableMap)
			if err != nil {
				wrappedErr := errors.Wrapf(err, "Evalaute expression error: %s", expression)
				logger.Error(wrappedErr)
				continue
			}

			// 设置variableMap并且更新CompileOption
			switch value := out.Value().(type) {
			case *model.UrlType:
				if _, ok := variableMap[k]; !ok {
					c.UpdateCompileOption(k, helper.UrlTypeType)
				}
				variableMap[k] = helper.UrlTypeToString(value)
			case *model.Reverse:
				if _, ok := variableMap[k]; !ok {
					c.UpdateCompileOption(k, helper.ReverseType)
				}
				variableMap[k] = value
			case int, int32, int64:
				if _, ok := variableMap[k]; !ok {
					c.UpdateCompileOption(k, decls.Int)
				}
				variableMap[k] = value
			case map[string]string:
				if _, ok := variableMap[k]; !ok {
					c.UpdateCompileOption(k, helper.StrStrMapType)
				}
				variableMap[k] = value
			case string:
				if _, ok := variableMap[k]; !ok {
					c.UpdateCompileOption(k, decls.String)
				}
				variableMap[k] = value
			default:
				if _, ok := variableMap[k]; !ok {
					c.UpdateCompileOption(k, decls.Any)
				}
				variableMap[k] = value
			}
			// ? 需要重新生成一遍环境，否则之前增加的变量定义不生效
			globalEnv, err = ReCreateEnv(c)
			if err != nil {
				return err
			}
		}
		return nil
	}

	// 处理set
	if err := evaluateUpdateVariableMap(poc.Set); err != nil {
		logger.Error(err)
		return err
	}

	// 渲染detail
	detail := &poc.Detail
	detail.Author = render(detail.Author)
	for k, v := range poc.Detail.Links {
		detail.Links[k] = render(v)
	}

	if fp := detail.Fingerprint; fp != nil {
		for _, info := range fp.Infos {
			info.ID = render(info.ID)
			info.Name = render(info.Name)
			info.Version = render(info.Version)
			info.Type = render(info.Type)
		}
		if fp.HostInfo != nil {
			fp.HostInfo.Hostname = render(fp.HostInfo.Hostname)
		}
	}

	if vulnerability := detail.Vulnerability; vulnerability != nil {
		vulnerability.ID = render(vulnerability.ID)
		vulnerability.Match = render(vulnerability.Match)
	}

	// transport=http: request处理
	HttpRequestInvoke := func(oRule any) error {
		var err error
		rule, _ := oRule.(Rule)
		var ruleReq = rule.Request
		// 渲染请求头，请求路径和请求体
		for k, v := range ruleReq.Headers {
			ruleReq.Headers[k] = render(v)
		}
		ruleReq.Path = render(strings.TrimSpace(ruleReq.Path))
		ruleReq.Body = render(strings.TrimSpace(ruleReq.Body))
		protoRequest, err = helper.ConvertHttpRequestToModelRequest(flow.Request)
		addr = utils.UrlJoinPath(flow.Request.URL().String(), ruleReq.Path)
		// 克隆请求对象
		request, err = http.NewRequest(ruleReq.Method, addr, strings.NewReader(ruleReq.Body))
		if err != nil {
			return err
		}
		// 处理请求头
		request.SetHeaders(ruleReq.Headers)

		protoRequest.RawHeader, _ = request.DumpHeader(nil)
		protoRequest.Raw = request.Dump()
		snapShot = append(snapShot, string(protoRequest.Raw))
		oResponse, err := ab.HTTPClient.Respond(ctx, request)
		if err != nil {
			return err
		}
		milliseconds := oResponse.TimeStamp - request.TimeStamp
		protoResponse, err = helper.ConvertHttpResponseToModelResponse(oResponse, milliseconds)
		snapShot = append(snapShot, string(protoResponse.Raw))

		flows = append(flows, &http.Flow{Request: request, Response: oResponse})
		return nil
	}

	// 处理请求完毕后的结果, 处理每个规则的通用表达式
	RequestInvoke := func(requestFunc helper.RequestFuncType, ruleName string, orule any) (bool, error) {
		var (
			flag bool
			ok   bool
			err  error
		)
		var rule = orule.(Rule)
		err = requestFunc(rule)
		if err != nil {
			return false, err
		}
		variableMap["request"] = protoRequest
		variableMap["response"] = protoResponse
		// 执行表达式
		out, err := helper.Evaluate(globalEnv, rule.Expression, variableMap)

		if err != nil {
			wrappedErr := errors.Wrapf(err, "Evalute %s rule[%s] expression error: %s", y.Name, ruleName, rule.Expression)
			logger.Errorf(wrappedErr.Error())
			return false, wrappedErr
		}

		// 判断表达式结果
		flag, ok = out.Value().(bool)
		if !ok {
			flag = false
		}

		// 处理output
		if err := evaluateUpdateVariableMap(rule.Output); err != nil {
			return false, err
		}

		return flag, nil
	}
	requestFunc = HttpRequestInvoke
	ruleSlice := poc.Rules
	// 提前定义名为ruleName的函数
	for _, ruleItem := range ruleSlice {
		c.DefineRuleFunction(requestFunc, ruleItem.Key, ruleItem.Value, RequestInvoke)
		if err != nil {
			wrappedErr := errors.Wrapf(err, "Define %s error", ruleItem.Key)
			return wrappedErr
		}
	}
	// ? 最后再生成一遍环境，否则之前增加的变量定义不生效
	globalEnv, err = ReCreateEnv(c)
	if err != nil {
		logger.Error(err)
		return err
	}

	// 执行rule 并判断poc总体表达式结果
	run := func() (bool, error) {
		successVal, err := helper.Evaluate(globalEnv, poc.Expression, variableMap)
		if err != nil {
			wrappedErr := errors.Wrapf(err, "Evalute poc[%s] expression error: %s", poc.Name, poc.Expression)
			logger.Error(wrappedErr.Error())
			return false, wrappedErr
		}

		isVul, ok := successVal.Value().(bool)
		if !ok {
			isVul = false
		}

		return isVul, nil
	}

	// 如果没设置payload，则直接评估rules并返回
	if len(poc.Payloads.Payloads) == 0 {
		isVul, err := run()
		if isVul {
			result := ab.NewWebVuln(flow.Request, flow.Response, nil)
			result.SetTargetURL(flow.Request.URL())
			if y.poc.Detail.Author != "" {
				result.Add("Author", y.poc.Detail.Author)
			}
			if len(y.poc.Detail.Links) > 0 {
				result.AddStringArray("Links", y.poc.Detail.Links)
			}
			if len(y.poc.Detail.Description) > 0 {
				result.Add("Description", y.poc.Detail.Description)
			}
			if y.pocPath != "" {
				result.Add("PocPath", y.pocPath)
			}
			result.Flow = flows
			// result := model.NewWebScanResult(y.poc.Name, flow.Request.URL().String())
			//result.Data.ReferenceLinks = poc.Detail.Links
			//result.Data.Detail.SnapShot = snapShot
			//result.Data.Description = poc.Detail.Description
			ab.OutputVuln(result)
			return nil
		}
		return err
	} else {
		for _, setMapVal := range poc.Payloads.Payloads {
			payloads := setMapVal.Value.(yaml.MapSlice)
			evaluateUpdateVariableMap(payloads)
			isVul, err = run()
			if err != nil {
				return err
			}
			if isVul && !poc.Payloads.Continue {
				result := ab.NewWebVuln(flow.Request, flow.Response, nil)
				result.SetTargetURL(flow.Request.URL())
				if y.poc.Detail.Author != "" {
					result.Add("Author", y.poc.Detail.Author)
				}
				if len(y.poc.Detail.Links) > 0 {
					result.AddStringArray("Links", y.poc.Detail.Links)
				}
				if len(y.poc.Detail.Description) > 0 {
					result.Add("Description", y.poc.Detail.Description)
				}
				if y.pocPath != "" {
					result.Add("PocPath", y.pocPath)
				}
				result.Flow = flows
				//result.Data.Name = poc.Name
				//result.Data.Description = poc.Detail.Description
				ab.OutputVuln(result)
				return nil
			}
		}
	}
	return nil
}

func (y *YamlFinger) Finger() *base.Finger {
	f := &base.Finger{
		Channel:    "web-directory",
		Binding:    &model.VulnBinding{ID: y.poc.Name, Plugin: y.poc.Name, Category: y.poc.Name, Severity: model.SeverityHigh},
		ExecAction: y.Run,
	}
	for _, item := range y.poc.Set {
		v := item.Value.(string)
		if strings.Contains(v, "newReverse") {
			f.NeedReverse = true
			break
		}
	}
	return f
}

func YamlFingerDump(poc *Poc) *YamlFinger {
	return &YamlFinger{
		poc: poc,
	}
}
