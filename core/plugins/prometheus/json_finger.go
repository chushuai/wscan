/**
2 * @Author: shaochuyu
3 * @Date: 12/30/23
4 */

package prometheus

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/plugins/prometheus/goby"
	"wscan/core/plugins/prometheus/goby/proto"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

type JsonFinger struct {
	poc     *goby.Poc
	init    func(context.Context, *base.Apollo) // transport.Target
	pocPath string
}

func (y *JsonFinger) Finger() *base.Finger {
	return &base.Finger{
		Channel:    "web-directory",
		Binding:    &model.VulnBinding{ID: y.poc.Name, Plugin: y.poc.Name, Category: y.poc.Name, Severity: model.SeverityHigh},
		ExecAction: y.Run,
	}
}

func (y *JsonFinger) Run(ctx context.Context, ab *base.Apollo) (err error) {
	var scanOperation string
	var output []bool
	addr := ""
	flow := ab.GetTargetFlow()
	logger.Infof("Running %s %s", y.poc.Name, flow.Request.URL().String())
	flows := []*http.Flow{}
	for _, step := range y.poc.ScanSteps {
		if step == "AND" {
			scanOperation = "AND"
			continue
		} else if step == "OR" {
			scanOperation = "OR"
			continue
		}
		// 解析 rule
		var bytes []byte
		bytes, err = json.Marshal(step)
		if err != nil {
			return
		}
		var rule goby.Rule
		err = json.Unmarshal(bytes, &rule)
		if err != nil {
			return
		}
		// 请求
		var protoResp *proto.Response
		addr = utils.UrlJoinPath(flow.Request.URL().String(), rule.Request.Uri)
		parseUrl, err := url.Parse(addr)
		if err != nil {
			return err
		}
		request, err := http.NewRequest(rule.Request.Method, addr, strings.NewReader(rule.Request.Data))
		if err != nil {
			return err
		}
		resp, err := ab.HTTPClient.Respond(context.Background(), request)
		if err != nil {
			return err
		}
		addr = request.URL().String()
		flows = http.AddFlow(flows, &http.Flow{Request: request, Response: resp}, 5)
		protoResp = &proto.Response{
			Url:         goby.UrlToPUrl(parseUrl),
			Status:      int32(resp.StatusCode),
			Headers:     resp.GetHeaderMap(),
			ContentType: resp.GetContentType(),
			Body:        resp.GetRawBody(),
		}
		out := rule.CheckResult(protoResp)
		output = append(output, out)
	}
	result := false
	if len(output) > 0 {
		if scanOperation == "AND" {
			flag := true
			for _, out := range output {
				if !out {
					flag = false
					break
				}
			}
			if flag {
				result = true
			}
		} else if scanOperation == "OR" {
			flag := false
			for _, out := range output {
				if out {
					flag = true
					break
				}
			}
			if flag {
				result = true
			}
		}
	}

	if result {
		ret := ab.NewWebVuln(flow.Request, flow.Response, nil)
		ret.Flow = flows
		if u, err := url.Parse(addr); err == nil {
			ret.SetTargetURL(u)
		} else {
			ret.SetTargetURL(flow.Request.URL())
		}
		if y.poc.Description != "" {
			ret.Add("Description", y.poc.Description)
		}
		if y.pocPath != "" {
			ret.Add("PocPath", y.pocPath)
		}
		ab.OutputVuln(ret)
	}
	return
}
