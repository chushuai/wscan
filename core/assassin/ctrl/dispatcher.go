/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package ctrl

import (
	"github.com/panjf2000/ants/v2"
	"golang.org/x/net/context"
	"wscan/core/assassin/http"
	"wscan/core/assassin/plugins/base"
	"wscan/core/utils/checker"
)

type Dispatcher struct {
	plugins       []base.Plugin
	pluginConfig  map[string]base.PluginConfigInterface
	config        *Config
	httpStat      *http.Statistics
	httpClient    *http.Client
	bifrostBase   *base.BifrostBase
	fingerCount   map[int]int
	requestFilter *checker.RequestChecker
	serviceFilter *checker.ServiceChecker
	ctx           context.Context
	cancel        func()
	reactor       *ants.Pool
	root          *Node
	evBus         *EventBus
	nextCounter   int32
	done          chan struct{}
	retestErr     error
	hasRun        bool
}

func (*Dispatcher) DumpSvg() string {
	return ""
}
func (*Dispatcher) EnabledPlugins() {

}
func (*Dispatcher) Init(bool) error {
	return nil
}
func (*Dispatcher) Release() {

}
func (*Dispatcher) Retest() {

}
func (*Dispatcher) Run() {

}
func (*Dispatcher) Wait(context.Context) {

}
func (*Dispatcher) buildTree() {

}
func (*Dispatcher) findNode() {

}
func (*Dispatcher) makeLeftNodeDone() {

}
func (*Dispatcher) publishToNode() {

}
func (*Dispatcher) rmNode() {

}
func (*Dispatcher) statistic(context.Context) {

}
func (*Dispatcher) traversalTree() {

}
func (*Dispatcher) trimHeader(map[string][]string) {}

func NewDispatcher() {

}

func NewNode() {

}

func NewNodeFromParent() {

}
