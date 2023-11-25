/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package base

import (
	"context"
	"wscan/core/model"
)

// 所有扫描逻辑定义在Finger的回调函数中
type Finger struct {
	Binding         *model.VulnBinding
	RelyOn          *model.VulnBinding
	Channel         string
	NeedReverse     bool
	NeedStandalone  bool
	NeedTransaction bool
	InitAction      func(context.Context, *ApolloBase) error
	CheckAction     func(context.Context, *Apollo) error
	ExecAction      func(context.Context, *Apollo) error
	ReTestAction    func(context.Context, *Apollo) error
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
	Init(context.Context, PluginConfigInterface, *ApolloBase) error
}
