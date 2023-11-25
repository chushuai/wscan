/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package matcher

import (
	"fmt"
	"sync"
)

type KeyMatcher struct {
	inserted bool
	sync.Map
}

func NewKeyMatcher() *KeyMatcher {
	return &KeyMatcher{}
}

func (km *KeyMatcher) Add(keys []string) error {
	if len(keys) == 0 {
		return fmt.Errorf("no keys provided")
	}
	for _, key := range keys {
		km.Store(key, true)
	}
	return nil
}

func (km *KeyMatcher) IsEmpty() bool {
	isEmpty := true
	km.Range(func(_, _ interface{}) bool {
		isEmpty = false
		return false
	})
	return isEmpty
}

func (km *KeyMatcher) Match(key string) bool {
	_, ok := km.Load(key)
	return ok
}
