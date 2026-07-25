/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package mitmhelper

import (
	"text/template"
	"wscan/core/http"
)

type WebCtrlPageModifier struct {
	CaCert      string
	WebCtrlPage *template.Template
}

func (*WebCtrlPageModifier) ModifyRequest(*http.Request) error {
	return nil
}

func (*WebCtrlPageModifier) ModifyResponse(*http.Response) error {
	return nil
}

func (*WebCtrlPageModifier) getCaCertContent() (string, error) {
	return "", nil
}
