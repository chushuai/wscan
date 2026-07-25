/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package base

import (
	"context"
	"wscan/core/model"
)

// Finger represents a detection rule with check and execute callbacks.
// All scanning logic is defined in the callback functions of Finger.
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
