/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package mitmhelper

import "wscan/core/http"

type FixAcceptEncodingModifier struct{}

func (*FixAcceptEncodingModifier) ModifyRequest(*http.Request) error {

	return nil
}
