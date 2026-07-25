/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package ctrl

import (
	"context"
	"sync"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/resource"
)

type Statistics struct {
}

type BasicRunner struct {
	check   func(context.Context, *base.Apollo) error
	exec    func(context.Context, *base.Apollo) error
	biBase  *base.ApolloBase
	binding *model.VulnBinding
	Next    func(context.Context, resource.Resource, func()) error
}

func (br *BasicRunner) Run(b resource.Resource) {

	bi := base.NewApollo(b)
	bi.ApolloBase = br.biBase
	bi.WithVuln(&model.Vuln{Binding: br.binding})
	if br.binding != nil {
		if br.check != nil {
			err := br.check(context.Background(), bi)
			if err == nil && br.exec != nil {
				br.exec(context.Background(), bi)
			}
		}
	}
	if br.Next != nil {
		br.Next(context.Background(), b, func() {
			// close
		})
	}
}

type Node struct {
	ID     string
	Level  int
	Data   *base.Finger
	Parent any
	Child  []*Node
}

type taskStatistic struct {
	sync.Mutex
	initial  int
	callback func()
}

func (ts *taskStatistic) SubTaskDone() {
	ts.Lock()
	defer ts.Unlock()

	if ts.initial == 0 && ts.callback != nil {
		ts.callback()
	}
}
