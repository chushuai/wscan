/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package ctrl

import (
	"context"
	"reflect"
	"sync"
	"wscan/core/assassin/model"
	"wscan/core/assassin/plugins/base"
	"wscan/core/assassin/resource"
)

type Statistics struct {
}

type BasicRunner struct {
	check   func(context.Context, *base.Bifrost) error
	exec    func(context.Context, *base.Bifrost) error
	biBase  *base.BifrostBase
	binding *model.VulnBinding
	Next    func(context.Context, resource.Resource, func()) error
}

type Node struct {
	ID     string
	Level  int
	Data   *base.Finger
	Parent *Node
	Child  []*Node
}

type eventHandler struct {
	callBack      reflect.Value
	flagOnce      bool
	async         bool
	transactional bool
	sync.Mutex
}

func (*eventHandler) Lock() {

}
func (*eventHandler) Unlock() {

}
func (*eventHandler) lockSlow() {

}
func (*eventHandler) unlockSlow(int32) {

}

type taskStatistic struct {
	sync.Mutex
	initial  int
	callback func()
}

func (*taskStatistic) Lock() {

}
func (*taskStatistic) SubTaskDone() {

}
func (*taskStatistic) Unlock() {

}
func (*taskStatistic) lockSlow() {

}
func (*taskStatistic) unlockSlow(int32) {

}
