/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package crawler

import (
	"github.com/go-redis/redis"
	"golang.org/x/net/context"
	"sync"
)

type Filter interface {
	Check(string, bool) bool
	Close()
	Insert(string)
	Reset()
}
type RedisFilter struct {
	ctx        context.Context
	keyCtx     context.Context
	keyCancel  func()
	client     *redis.Client
	key        string
	keyTimeout int64
	once       *sync.Once
}

type SyncMapFilter struct {
	*sync.Map
}
