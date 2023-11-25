/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package ctrl

import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
)

type EventBus struct {
	lock     sync.RWMutex
	handlers map[string][]*eventHandler
	wg       sync.WaitGroup
	pool     AsyncPool
}

func (*EventBus) GetCallbackCount(string) int {
	return 0
}

// HasCallback检查是否存在已订阅主题的回调函数
func (bus *EventBus) HasCallback(topic string) bool {
	bus.lock.Lock()
	defer bus.lock.Unlock()
	_, ok := bus.handlers[topic]
	if ok {
		return len(bus.handlers[topic]) > 0
	}
	return false
}

// Publish 执行定义的主题回调函数。 任何额外的参数将传递给回调函数。
func (bus *EventBus) Publish(topic string, args ...interface{}) {
	bus.lock.Lock() // 如果未找到处理程序或始终在setUpPublish后解锁
	defer bus.lock.Unlock()
	if handlers, ok := bus.handlers[topic]; ok && 0 < len(handlers) {
		// 处理程序切片可能会在迭代期间通过removeHandler和Unsubscribe进行更改，
		// 因此制作副本并迭代已复制的切片。
		copyHandlers := make([]*eventHandler, len(handlers))
		copy(copyHandlers, handlers)
		for i, handler := range copyHandlers {
			if handler.flagOnce {
				bus.removeHandler(topic, i)
			}
			if !handler.async {
				bus.doPublish(handler, topic, args...)
			} else {
				bus.wg.Add(1)
				if handler.transactional {
					bus.lock.Unlock()
					handler.Lock()
					bus.lock.Lock()
				}
				if bus.pool != nil {
					bus.pool.Submit(func(h *eventHandler, t string, a ...interface{}) func() {
						return func() {
							bus.doPublishAsync(h, t, a...)
						}
					}(handler, topic, args...))
				} else {
					go bus.doPublishAsync(handler, topic, args...)
				}
			}
		}
	}
}

// Subscribe 订阅主题。 如果fn不是函数，则返回错误。
func (bus *EventBus) Subscribe(topic string, fn interface{}) error {
	return bus.doSubscribe(topic, fn, &eventHandler{
		reflect.ValueOf(fn), false, false, false, sync.Mutex{},
	})
}

// SubscribeAsync 订阅异步回调主题, 事务性确定主题的后续回调是串行（true）还是并发（false）,如果fn不是函数，则返回错误。
func (bus *EventBus) SubscribeAsync(topic string, fn interface{}, transactional bool) error {
	return bus.doSubscribe(topic, fn, &eventHandler{
		reflect.ValueOf(fn), false, true, transactional, sync.Mutex{},
	})
}

// SubscribeOnce subscribes to a topic once. Handler will be removed after executing.
// Returns error if `fn` is not a function.
func (bus *EventBus) SubscribeOnce(topic string, fn interface{}) error {
	return bus.doSubscribe(topic, fn, &eventHandler{
		reflect.ValueOf(fn), true, false, false, sync.Mutex{},
	})
}

// SubscribeOnce 订阅主题一次。 处理程序将在执行后被删除。 如果fn不是函数，则返回错误
func (bus *EventBus) SubscribeOnceAsync(topic string, fn interface{}) error {
	return bus.doSubscribe(topic, fn, &eventHandler{
		reflect.ValueOf(fn), true, true, false, sync.Mutex{},
	})
}

// Unsubscribe 删除为主题定义的回调。 如果未订阅主题上存在任何回调，则返回错误。
func (bus *EventBus) Unsubscribe(topic string, handler interface{}) error {
	bus.lock.Lock()
	defer bus.lock.Unlock()
	if _, ok := bus.handlers[topic]; ok && len(bus.handlers[topic]) > 0 {
		bus.removeHandler(topic, bus.findHandlerIdx(topic, reflect.ValueOf(handler)))
		return nil
	}
	return fmt.Errorf("topic %s doesn't exist", topic)
}

// WaitAsync waits for all async callbacks to complete
func (bus *EventBus) WaitAsync() {
	bus.wg.Wait()
}

func (bus *EventBus) doPublish(handler *eventHandler, topic string, args ...interface{}) {
	passedArguments := bus.setUpPublish(handler, args...)
	handler.callBack.Call(passedArguments)
}

func (bus *EventBus) doPublishAsync(handler *eventHandler, topic string, args ...interface{}) {
	defer bus.wg.Done()
	if handler.transactional {
		defer handler.Unlock()
	}
	bus.doPublish(handler, topic, args...)
}

// doSubscribe handles the subscription logic and is utilized by the public Subscribe functions
func (bus *EventBus) doSubscribe(topic string, fn interface{}, handler *eventHandler) error {
	bus.lock.Lock()
	defer bus.lock.Unlock()
	if !(reflect.TypeOf(fn).Kind() == reflect.Func) {
		return fmt.Errorf("%s is not of type reflect.Func", reflect.TypeOf(fn).Kind())
	}
	bus.handlers[topic] = append(bus.handlers[topic], handler)
	return nil
}

func (bus *EventBus) findHandlerIdx(topic string, callback reflect.Value) int {
	if _, ok := bus.handlers[topic]; ok {
		for idx, handler := range bus.handlers[topic] {
			if handler.callBack.Type() == callback.Type() &&
				handler.callBack.Pointer() == callback.Pointer() {
				return idx
			}
		}
	}
	return -1
}

func (bus *EventBus) removeHandler(topic string, idx int) {
	if _, ok := bus.handlers[topic]; !ok {
		return
	}
	l := len(bus.handlers[topic])

	if !(0 <= idx && idx < l) {
		return
	}

	copy(bus.handlers[topic][idx:], bus.handlers[topic][idx+1:])
	bus.handlers[topic][l-1] = nil // or the zero value of T
	bus.handlers[topic] = bus.handlers[topic][:l-1]
}

func (bus *EventBus) setUpPublish(callback *eventHandler, args ...interface{}) []reflect.Value {
	funcType := callback.callBack.Type()
	passedArguments := make([]reflect.Value, len(args))
	for i, v := range args {
		if v == nil {
			passedArguments[i] = reflect.New(funcType.In(i)).Elem()
		} else {
			passedArguments[i] = reflect.ValueOf(v)
		}
	}

	return passedArguments
}

type AsyncPool interface {
	Release()
	Running() int
	Submit(func()) error
}

// 虚拟的AsyncPool
type DummyAsyncPool struct {
	running int32
}

func (dap *DummyAsyncPool) Release() {

}

func (dap *DummyAsyncPool) Running() int {
	return int(dap.running)
}

func (dap *DummyAsyncPool) Submit(fn func()) error {
	defer atomic.AddInt32(&dap.running, -1)
	atomic.AddInt32(&dap.running, 1)
	fn()
	return nil
}

func NewEventBus() *EventBus {
	b := &EventBus{}
	b.handlers = make(map[string][]*eventHandler)
	b.lock = sync.RWMutex{}
	b.wg = sync.WaitGroup{}
	return b
}

func NewEventBusWithAsyncPool(pool AsyncPool) *EventBus {
	b := NewEventBus()
	b.pool = pool
	return b
}

//BusSubscriber defines subscription-related bus behavior
type BusSubscriber interface {
	Subscribe(topic string, fn interface{}) error
	SubscribeAsync(topic string, fn interface{}, transactional bool) error
	SubscribeOnce(topic string, fn interface{}) error
	SubscribeOnceAsync(topic string, fn interface{}) error
	Unsubscribe(topic string, handler interface{}) error
}

//BusPublisher defines publishing-related bus behavior
type BusPublisher interface {
	Publish(topic string, args ...interface{})
}

//BusController defines bus control behavior (checking handler's presence, synchronization)
type BusController interface {
	HasCallback(topic string) bool
	WaitAsync()
}

//Bus englobes global (subscribe, publish, control) bus behavior
type Bus interface {
	BusController
	BusSubscriber
	BusPublisher
}

type eventHandler struct {
	callBack      reflect.Value
	flagOnce      bool
	async         bool
	transactional bool
	sync.Mutex    // lock for an event handler - useful for running async callbacks serially
}

// New returns new EventBus with empty handlers.
func New() Bus {
	b := &EventBus{}
	b.handlers = make(map[string][]*eventHandler)
	b.lock = sync.RWMutex{}
	b.wg = sync.WaitGroup{}
	return Bus(b)
}
