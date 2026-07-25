/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import (
	"context"
	"sync"
)

type SizedWaitGroup struct {
	wg      sync.WaitGroup
	current chan struct{}
}

// 创建一个具有指定并发数的 SizedWaitGroup
func NewSizedWaitGroup(concurrency int) *SizedWaitGroup {
	return &SizedWaitGroup{
		current: make(chan struct{}, concurrency),
	}
}

// 增加计数器并等待可用的并发数
func (swg *SizedWaitGroup) Add() {
	swg.current <- struct{}{}
	swg.wg.Add(1)
}

// 增加计数器并等待可用的并发数或上下文取消
func (swg *SizedWaitGroup) AddWithContext(ctx context.Context) error {
	select {
	case swg.current <- struct{}{}:
		swg.wg.Add(1)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// 减少计数器并释放一个并发数
func (swg *SizedWaitGroup) Done() {
	<-swg.current
	swg.wg.Done()
}

// 等待所有并发操作完成
func (swg *SizedWaitGroup) Wait() {
	swg.wg.Wait()
}
