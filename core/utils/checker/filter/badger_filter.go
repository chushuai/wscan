/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package filter

import (
	"github.com/dgraph-io/badger/v3"
	"golang.org/x/net/context"
	"log"
	"sync"
)

type BadgerFilter struct {
	sync.Mutex
	ctx    context.Context
	cancel func()
	logger *log.Logger
	db     *badger.DB
	dbPath string
	closed bool
}
