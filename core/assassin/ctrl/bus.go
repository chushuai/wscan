/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package ctrl

import "sync"

type EventBus struct {
	lock     sync.RWMutex
	handlers map[string][]*eventHandler
	wg       sync.WaitGroup
	pool     AsyncPool
}

func (*EventBus) GetCallbackCount(string) int {
	return 0
}
func (*EventBus) HasCallback(string) bool {
	return false
}
func (*EventBus) Publish() {

}
func (*EventBus) Subscribe(string, interface{}) error {
	return nil
}
func (*EventBus) SubscribeAsync() {

}
func (*EventBus) SubscribeOnce(string, interface{}) error {
	return nil
}
func (*EventBus) SubscribeOnceAsync(string, interface{}) error {
	return nil
}
func (*EventBus) Unsubscribe(string, interface{}) error {
	return nil
}
func (*EventBus) WaitAsync() {

}
func (*EventBus) doPublish() {

}
func (*EventBus) doPublishAsync() {

}
func (*EventBus) doSubscribe() {

}
func (*EventBus) findHandlerIdx() {

}
func (*EventBus) removeHandler() {

}
func (*EventBus) setUpPublish() {

}

type AsyncPool interface {
	Release()
	Running() int
	Submit(func()) error
}

type DummyAsyncPool struct {
	running int32
}

func (*DummyAsyncPool) Release() {

}
func (*DummyAsyncPool) Running() int {
	return 0
}
func (*DummyAsyncPool) Submit(func()) error {
	return nil
}

func NewEventBus() {

}

func NewEventBusWithAsyncPool() {

}
