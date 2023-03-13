/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package filter

import (
	"encoding/binary"
	"errors"
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

// BadgerFilter 实现 Filter 接口
func (bf *BadgerFilter) Close() error {
	bf.cancel()
	bf.closed = true
	return bf.db.Close()
}

// 将 int64 类型转换为 []byte 类型
func int64ToBytes(i int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(i))
	return buf
}

// 将 []byte 类型转换为 int64 类型
func bytesToInt64(b []byte) int64 {
	return int64(binary.BigEndian.Uint64(b))
}

func (bf *BadgerFilter) Insert(key string, value int64) {
	b := int64ToBytes(value)
	err := bf.db.Update(func(txn *badger.Txn) error {
		err := txn.Set([]byte(key), b)
		return err
	})
	if err != nil {
		bf.logger.Printf("Error inserting key-value pair into Badger database: %v", err)
	}
}

func (bf *BadgerFilter) IsInserted(key string, shouldLock bool, value int64) bool {
	if shouldLock {
		bf.Lock()
		defer bf.Unlock()
	}
	err := bf.db.View(func(txn *badger.Txn) error {
		val, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		return val.Value(func(existing []byte) error {
			existingVal := bytesToInt64(existing)
			if existingVal < value {
				return errors.New("value not found")
			}
			return nil
		})
	})
	if err != nil {
		bf.logger.Printf("Error checking if key-value pair (%s, %d) is inserted: %s\n", key, value, err)
		return false
	}
	return true
}

func (bf *BadgerFilter) Reset() error {
	bf.Lock()
	defer bf.Unlock()
	bf.logger.Printf("Resetting Badger filter\n")
	if err := bf.db.DropAll(); err != nil {
		return err
	}
	return nil
}
