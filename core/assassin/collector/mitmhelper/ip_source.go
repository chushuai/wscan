/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package mitmhelper

import (
	"wscan/core/assassin/http"
	"wscan/core/assassin/utils"
)

type AllowedIPSourceModifier struct {
	IPRange *utils.IPRange
}

func (*AllowedIPSourceModifier) ModifyRequest(*http.Request) error {

	return nil
}
func (*AllowedIPSourceModifier) ModifyResponse(*http.Response) error {
	return nil
}
