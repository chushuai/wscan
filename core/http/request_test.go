/**
2 * @Author: shaochuyu
3 * @Date: 12/12/22
4 */

package http

import (
	"fmt"
	"testing"
	logger "wscan/core/utils/log"
)

func TestRequest(t *testing.T) {
	logger.Info("Test request")
	url := "http://47.98.142.136:8901/timer/login/loginManage"
	postData := "userName=q&passWord=1"
	req, err := RequestFromRawURL(url)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(req)
	fmt.Println(url, postData)

}
