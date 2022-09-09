/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import (
	"sync"
	"wscan/core/assassin/resource"
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

func (*Request) DeepClone() *Request {
	return nil
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
