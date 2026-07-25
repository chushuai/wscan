/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import (
	"sync"
	"wscan/core/resource"
)

type compiledProxyRule struct {
	sync.Mutex
	//match   glob.Glob
	//servers weighted.RRW
}

type flowDispatcher struct {
	callbacks []func(*Flow)
}

func (r *Request) Timestamp() int64 {
	return r.TimeStamp
}

func (*Request) String() string {
	return ""
}

func (r *Request) DeepClone() *Request {
	newReq := new(Request)
	*newReq = *r
	newReq.url = cloneURL(r.url)
	if newReq.Header != nil {
		newReq.Header = cloneHeader(r.Header)
	}
	// TODO 这里需要深拷贝
	//newReq.bodyParams = cloneParameters(r.bodyParams)
	//newReq.queryParams = cloneParameters(r.queryParams)
	newReq.doCache()
	return newReq
}

func (f *Flow) DeepClone() resource.Resource {
	newFlow := &Flow{
		Request:   f.Request.DeepClone(),
		Response:  f.Response,
		History:   f.History,
		TimeStamp: f.TimeStamp,
	}
	return newFlow
}

func (f *Flow) Name() string {
	return ""
}

func (f *Flow) String() string {
	return ""
}

func (f *Flow) Timestamp() int64 {
	return f.TimeStamp
}

func (f *Flow) Type() int {
	return 0
}
