/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package gopoc

import "wscan/core/plugins/base"

type ecologyDBConfigInfoLeak struct{}

func (*ecologyDBConfigInfoLeak) Finger() *base.Finger {
	return nil
}
