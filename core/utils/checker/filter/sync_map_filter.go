/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package filter

import (
	"context"
	"sync"
)

type SyncMapFilter struct {
	sync.Mutex
	ctxOuter context.Context
	ctx      context.Context
	cancel   func()
	m        *sync.Map
	once     sync.Once
	closed   bool
}
