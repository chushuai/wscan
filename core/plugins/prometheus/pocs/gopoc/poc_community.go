/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package gopoc

import "wscan/core/plugins/base"

func LoadGolangPOC() (golangPoc []base.FingerFactory) {
	// golangPoc = append(golangPoc, &tomcatPut{})
	golangPoc = append(golangPoc, &log4jRce{})
	return
}
