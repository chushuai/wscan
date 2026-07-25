/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package gopoc

import "wscan/core/plugins/base"

type tongdaLFIRCE struct{}

func (*tongdaLFIRCE) Finger() *base.Finger {
	return nil
}

func (*tongdaLFIRCE) checkVuln() {

}
