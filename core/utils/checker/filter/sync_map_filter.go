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

// SyncMapFilter 实现 Filter 接口
func (sf *SyncMapFilter) Close() error {
	sf.cancel()
	sf.closed = true
	return nil
}

func (sf *SyncMapFilter) Insert(key string, value int64) {
	sf.m.Store(key, value)
}

func (sf *SyncMapFilter) IsInserted(key string, shouldLock bool, value int64) bool {
	sf.Lock()
	defer sf.Unlock()
	existingValue, ok := sf.m.Load(key)
	if !ok {
		return false
	}
	existingInt64, ok := existingValue.(int64)
	if !ok {
		return false
	}
	if existingInt64 < value {
		return false
	}
	return true
}

func (sf *SyncMapFilter) Reset() error {
	sf.Lock()
	defer sf.Unlock()
	sf.m = new(sync.Map)
	return nil
}
