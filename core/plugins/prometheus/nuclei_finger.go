/**
2 * @Author: shaochuyu
3 * @Date: 1/21/24
4 */

package prometheus

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

type NucleiFinger struct {
	poc          *templates.Template
	init         func(context.Context, *base.Apollo) // transport.Target
	pocPath      string
	scanRootOnly bool // 0 - 没有限制, 1 - 表示只扫描根目录
}

func (NucleiFinger) Dump() ([]byte, error) {
	return nil, nil
}

//func (YamlFinger) GetExpression() (*expression.Expression, error) {
//	return nil, nil
//}

func (NucleiFinger) Init(bool) error {
	return nil
}
func (NucleiFinger) MarshalYAML() (any, error) {
	return nil, nil
}

//func (YamlFinger) UnmarshalYAML(*yaml.Node) error {
//	return nil
//}

func (NucleiFinger) compileNode() {

}
func (NucleiFinger) compilePayloads() {

}
func (NucleiFinger) run() {

}

func (y NucleiFinger) Run(ctx1 context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	if y.scanRootOnly && flow.Request.GetURLDepth() > 0 {
		logger.Infof("Skip Nuclei %s scan root only %s", y.poc.Path, flow.Request.URL().String())
		return nil
	}
	logger.Infof("Running Nuclei %s %s", y.poc.Path, flow.Request.URL().String())

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()
	scanCtx := scan.NewScanContext(ctx, contextargs.NewWithInput(ctx, flow.Request.URL().String()))
	var lastMatcherEvent *output.InternalWrappedEvent
	scanCtx.OnResult = func(event *output.InternalWrappedEvent) {
		if event == nil {
			return
		}
		if event.HasOperatorResult() && event.OperatorsResult.Matched && event.OperatorsResult.Operators != nil {
			allInternalMatchers := true
			for _, matcher := range event.OperatorsResult.Operators.Matchers {
				if allInternalMatchers && !matcher.Internal {
					allInternalMatchers = false
					break
				}
			}
			if allInternalMatchers {
				return
			}
		}
		if !event.HasOperatorResult() && event.InternalEvent != nil {

		} else {
			lastMatcherEvent = event
		}
	}

	switch y.poc.Type() {
	case types.WorkflowProtocol:
		return nil
	default:
		results, err := y.poc.Executer.ExecuteWithResults(scanCtx)
		if err != nil {
			return err
		}
		if lastMatcherEvent != nil {
			for _, resultEvent := range results {
				result := ab.NewWebVuln(flow.Request, flow.Response, nil)
				f := http.BuildFlow(resultEvent.Request, resultEvent.Response)
				if f != nil {
					result.Flow = []*http.Flow{f}
				}
				if len(resultEvent.URL) > 0 {
					if u, err := url.Parse(resultEvent.URL); err == nil {
						result.SetTargetURL(u)
					}
				}
				if resultEvent.MatcherName != "" {
					result.Add("MatcherName", resultEvent.MatcherName)
				}
				if len(resultEvent.Info.Description) > 0 {
					result.Add("Description", resultEvent.Info.Description)
				}
				if y.pocPath != "" {
					result.Add("PocPath", y.pocPath)
				}
				if resultEvent.CURLCommand != "" {
					result.Add("CURLCommand", resultEvent.CURLCommand)
				}
				if data, err := json.Marshal(resultEvent); err == nil {
					result.Add("json_str", string(data))
				}
				ab.OutputVuln(result)
			}
		}
	}

	return nil
}

func (y *NucleiFinger) Finger() *base.Finger {
	f := &base.Finger{
		Channel:    "web-directory",
		Binding:    &model.VulnBinding{ID: y.poc.ID, Plugin: y.poc.ID, Category: y.poc.ID, Severity: model.SeverityHigh},
		ExecAction: y.Run,
	}

	return f
}
