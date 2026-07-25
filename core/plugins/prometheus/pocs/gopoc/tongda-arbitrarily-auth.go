/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package gopoc

import (
	"wscan/core/plugins/base"
)

type tongdaArbitraryAuth struct{}

func (*tongdaArbitraryAuth) Finger() *base.Finger {
	return nil
}

//func (*tongdaArbitraryAuth) get2017Session(context.Context, *http.Request, *base.Bifrost) (string, error) {
//	return "", nil
//}
//
//func (*tongdaArbitraryAuth) getV11Session(context.Context, *http.Request, *base.Bifrost) (string, error) {
//	return "", nil
//}
