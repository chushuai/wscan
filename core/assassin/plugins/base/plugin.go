/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package base

import (
	"context"
	"wscan/core/assassin/model"
)

// 所有扫描逻辑定义在Finger的回调函数中
type Finger struct {
	Binding         *model.VulnBinding
	RelyOn          *model.VulnBinding
	Channel         string
	NeedReverse     bool
	NeedStandalone  bool
	NeedTransaction bool
	InitAction      func(context.Context, *BifrostBase) error
	CheckAction     func(context.Context, *Bifrost) error
	ExecAction      func(context.Context, *Bifrost) error
	ReTestAction    func(context.Context, *Bifrost) error
	CloseAction     func() error
}

type PluginMixinClose struct{}

func (*PluginMixinClose) Close() {

}

type FingerFactory interface {
	Finger() *Finger
}

type Plugin interface {
	Close() error
	DefaultConfig() PluginConfigInterface
	Fingers() []*Finger
	GetConfig() PluginConfigInterface
	Init(context.Context, PluginConfigInterface, *BifrostBase) error
}
