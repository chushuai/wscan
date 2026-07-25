/**
2 * @Author: shaochuyu
3 * @Date: 6/25/23
4 */

package prometheus

import (
	"net/http"
	"wscan/core/model"
)

type HttpRequestCache struct {
	Request       *http.Request
	ProtoRequest  *model.Request
	ProtoResponse *model.Response
}

type TCPUDPRequestCache struct {
	Response      []byte
	ProtoResponse *model.Response
}
