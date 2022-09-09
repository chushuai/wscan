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
