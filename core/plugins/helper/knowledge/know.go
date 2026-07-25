/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package knowledge

import (
	"context"
	"fmt"
	"github.com/thoas/go-funk"
	"net/http"
	"sync"
	"wscan/core/resource"
	"wscan/core/utils/checker/filter"
)

type KBItem struct {
	sync.Mutex
	m map[string]any
}

func (k *KBItem) Exist(key string) bool {
	k.Lock()
	defer k.Unlock()
	_, ok := k.m[key]
	return ok
}

func (k *KBItem) Get(key string) any {
	k.Lock()
	defer k.Unlock()
	return k.m[key]
}

func (k *KBItem) Remove(key string) {
	k.Lock()
	defer k.Unlock()
	delete(k.m, key)
}

func (k *KBItem) Set(key string, value any) {
	k.Lock()
	defer k.Unlock()
	k.m[key] = value
}

func NewKBItem() *KBItem {
	kbItem := &KBItem{
		m: make(map[string]any),
	}
	kbItem.m["fingerprint"] = []string{}
	return kbItem
}

type KnowledgeDB struct {
	rw         sync.RWMutex
	httpClient *http.Client
	checkRules []func(context.Context, resource.Resource) error
	filter     filter.Filter
	stub       map[string]*KBItem
}

func (k *KnowledgeDB) Close() {
	k.filter.Close()
}

func (k *KnowledgeDB) Process(ctx context.Context, res resource.Resource) {
	resCopy := res.DeepClone()
	// 指纹识别
	for _, rule := range k.checkRules {
		err := rule(ctx, resCopy)
		if err != nil {
			fmt.Printf("Error processing resource: %s\n", err.Error())
			return
		}
	}
}

func (k *KnowledgeDB) Resolve(res resource.Resource) *KBItem {
	k.rw.RLock()
	defer k.rw.RUnlock()
	key := "xxxx"
	if kbItem, exist := k.stub[key]; exist {
		return kbItem
	}
	k.stub[key] = NewKBItem()

	return k.stub[key]
}

func (k *KnowledgeDB) Get(key string) *KBItem {
	k.rw.RLock()
	defer k.rw.RUnlock()
	item, ok := k.stub[key]
	if !ok {
		return nil
	}
	return item
}

func (k *KnowledgeDB) Save(key string, item *KBItem) {
	k.rw.Lock()
	defer k.rw.Unlock()
	k.stub[key] = item
}

func (k *KnowledgeDB) SaveFingerprint(res resource.Resource, fingerprint string) bool {
	item := k.Resolve(res)
	item.Lock()
	defer item.Unlock()
	fingerprints := item.m["fingerprint"].([]string)
	if !funk.ContainsString(fingerprints, fingerprint) {
		item.m["fingerprint"] = append(fingerprints, fingerprint)
		return true
	}
	return false
}

func (k *KnowledgeDB) checkDVWA(ctx context.Context, res resource.Resource) {

}

func (k *KnowledgeDB) checkPHP(ctx context.Context, res resource.Resource) {

}

func (k *KnowledgeDB) checkStruts(ctx context.Context, res resource.Resource) {

}

func (k *KnowledgeDB) saveResult() {

}

func (k *KnowledgeDB) AddCheckRule(f func(context.Context, resource.Resource) error) {
	k.checkRules = append(k.checkRules, f)

}

func NewKnowledgeDB(filter filter.Filter) *KnowledgeDB {
	return &KnowledgeDB{
		httpClient: &http.Client{},
		checkRules: []func(context.Context, resource.Resource) error{},
		filter:     filter,
		stub:       make(map[string]*KBItem),
	}
}
