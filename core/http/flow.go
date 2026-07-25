/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import (
	"bufio"
	"net/http"
	"strings"
	"wscan/core/utils"
)

type Flow struct {
	Request   *Request
	Response  *Response
	History   []*Response
	TimeStamp int64
}

func (f *Flow) Seconds() int {
	return int((f.Response.TimeStamp - f.Request.TimeStamp) / int64(1000))
}

func MakeSnapShot(flows []Flow, maxLen int) (snapShot []any) {
	for _, flow := range flows {
		shot := []string{}
		shot = append(shot, utils.LimitStringLength(string(flow.Request.Dump()), maxLen))
		shot = append(shot, utils.LimitStringLength(string(flow.Response.Dump()), maxLen))
	}
	return
}

func AddFlow(flows []*Flow, flow *Flow, maxSize int) []*Flow {
	if len(flows) >= maxSize {
		flows = flows[1:]
	}
	flows = append(flows, flow)
	return flows
}

func BuildFlow(request string, response string) *Flow {

	hReq, err := http.ReadRequest(bufio.NewReader(strings.NewReader(request)))
	if err != nil {
		return nil
	}
	req, err := RequestFromNetHttpRequert(hReq)
	if err != nil {
		return nil
	}
	hRes, err := http.ReadResponse(bufio.NewReader(strings.NewReader(response)), hReq)
	if err != nil {
		return nil
	}
	res, err := ResponseFromNetHttpResponse(hRes)
	if err != nil {
		return nil
	}
	return &Flow{Request: req, Response: res}
}
