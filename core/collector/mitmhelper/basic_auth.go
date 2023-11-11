/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package mitmhelper

import "wscan/core/http"

type BasicAuthModifier struct {
	Username string
	Password string
}

func (*BasicAuthModifier) ModifyRequest(*http.Request) error {
	return nil
}
func (*BasicAuthModifier) ModifyResponse(*http.Response) error {
	return nil
}
