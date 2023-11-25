/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

type Flow struct {
	Request   *Request
	Response  *Response
	History   []*Response
	TimeStamp int64
}

func (f *Flow) Seconds() int {
	return int((f.Response.TimeStamp - f.Request.TimeStamp) / int64(1000))
}
