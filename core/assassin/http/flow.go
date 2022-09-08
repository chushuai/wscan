/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import "wscan/core/assassin/resource"

type Flow struct {
	Request   *Request
	Response  *Response
	History   []*Response
	TimeStamp int64
}

func (*Flow) DeepClone() resource.Resource {
	return nil
}
func (*Flow) Name() string {
	return ""
}
func (*Flow) String() string {
	return ""
}
func (*Flow) Timestamp() int64 {
	return 0
}
func (*Flow) Type() int {
	return 0
}
