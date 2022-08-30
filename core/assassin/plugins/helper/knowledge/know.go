/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package knowledge

import (
	"context"
	"go.opencensus.io/resource"
	"net/http"
	"sync"
	"wscan/core/utils/checker/filter"
)

type KBItem struct {
	sync.Mutex
	m map[string]interface{}
}

type KnowledgeDB struct {
	rw         sync.RWMutex
	httpClient *http.Client
	checkRules []func(context.Context, resource.Resource) error
	filter     filter.Filter
	stub       map[string]*KBItem
}
