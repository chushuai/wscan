/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package custom

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/plugins/helper"
	logger "wscan/core/utils/log"
)

type YamlFinger struct {
	*YamlScript
	init func(context.Context, *base.Apollo)
	cfg  *Config
}

func (y YamlFinger) Run(ctx context.Context, ab *base.Apollo) error {
	// 初始化cel-go环境，并在函数返回时回收
	ce := helper.NewCelExecutor()
	defer ce.Close()
	if err := ce.EvaluateUpdateVariableMap(y.Temp.Set); err != nil {
		logger.Error(err)
		return err
	}
	flow := ab.GetTargetFlow()
	for _, param := range flow.Request.ParamsQueryAndBody() {
		parameter := http.Parameter{Position: param.Position, Key: param.Key, Value: ce.Render(y.Payload)}
		req := flow.Request.Mutate(&parameter)
		res, err := ab.HTTPClient.Respond(context.TODO(), req)
		if err != nil {
			logger.Error(err)
			continue
		}
		protoRequest, err := helper.ConvertHttpRequestToModelRequest(req)
		protoResponse, err := helper.ConvertHttpResponseToModelResponse(res, res.TimeStamp-req.TimeStamp)
		ce.SetVariable("request", protoRequest)
		ce.SetVariable("response", protoResponse)
		successVal, err := ce.Evaluate(y.Temp.Expression)
		if err != nil {
			wrappedErr := errors.Wrapf(err, "Evalute poc[%s] expression error: %s", y.Temp.Name, y.Temp.Expression)
			logger.Error(wrappedErr.Error())
			return wrappedErr
		}
		isVul, ok := successVal.Value().(bool)
		if !ok {
			isVul = false
		}

		if isVul {
			v := ab.NewWebVuln(req, res, &param)
			if v != nil {
				v.SetTargetURL(flow.Request.URL())
				v.Param = &parameter
				ab.OutputVuln(v)
				break
			}
		}
	}
	return nil
}

func (y *YamlFinger) Finger() *base.Finger {
	return &base.Finger{
		Channel: y.Channel,
		Binding: &model.VulnBinding{ID: fmt.Sprintf("custom/%s", y.Temp.Name),
			Plugin:   fmt.Sprintf("custom/%s", y.Temp.Name),
			Category: fmt.Sprintf("custom/%s", y.Temp.Name)},
		ExecAction: y.Run,
	}
}
