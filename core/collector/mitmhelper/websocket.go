/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package mitmhelper

import "net/http"

type WebSocketModifier struct {
	TR                 *http.Transport
	writeExcludeHeader map[string]bool
	wsCanonicalHeader  []string
}

func (*WebSocketModifier) ModifyRequest(*http.Request) error {
	return nil
}
func (*WebSocketModifier) copySync() {

}
func (*WebSocketModifier) writeWSReq() {

}
