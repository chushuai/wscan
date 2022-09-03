/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package dns

import "sync"

type SW struct {
	items []*smoothWeighted
	n     int
}

type smoothWeighted struct {
	Item            interface{}
	Weight          int
	CurrentWeight   int
	EffectiveWeight int
}

// RoundRobin算法轮询调度算法的原理是每一次把来自用户的请求轮流分配给内部中的服务器从1开始直到n内部服务器个数然后重新开始循环
type DynamicRoundRobin struct {
	mu sync.Mutex
	SW
	lastServer string
}

func (*DynamicRoundRobin) Next() {

}
func (*DynamicRoundRobin) ResetWithWeigh() {

}
