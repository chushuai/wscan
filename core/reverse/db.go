/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"go.etcd.io/bbolt"
	"sort"
	"strconv"
	"sync"
	"time"
	logger "wscan/core/utils/log"
)

type Bucket struct {
	Name       string
	SubBuckets []Bucket
}

func (b *Bucket) Build(tx *bbolt.Tx, parent *bbolt.Bucket) {
	var bb *bbolt.Bucket
	var err error
	if parent == nil {
		if bb, err = tx.CreateBucketIfNotExists([]byte(b.Name)); err != nil {
			logger.Fatal(err)
		}
	} else {
		if bb, err = parent.CreateBucketIfNotExists([]byte(b.Name)); err != nil {
			logger.Fatal(err)
		}
	}
	for _, subBucket := range b.SubBuckets {
		subBucket.Build(tx, bb)
	}
}

var reverseBuiltinBuckets = []Bucket{
	{Name: "reverse_log", SubBuckets: []Bucket{{Name: "dns"}, {Name: "http"}, {Name: "rmi"}, {Name: "meta"}}},
	{Name: "reverse_group"},
	{Name: "resp_config"},
}

type DB struct {
	sync.Mutex
	path     string
	isTempDB bool
	*bbolt.DB
}

func (db *DB) Open(path string) error {
	db.Lock()
	defer db.Unlock()

	if db.DB != nil {
		return fmt.Errorf("database is already open")
	}
	bboltDB, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return err
	}
	db.path = path
	db.DB = bboltDB
	if err := db.Update(func(tx *bbolt.Tx) error {
		for _, bucket := range reverseBuiltinBuckets {
			bucket.Build(tx, nil)
		}
		return nil
	}); err != nil {
		logger.Fatal(err)
	}
	return nil
}

func (db *DB) Close() error {
	db.Lock()
	defer db.Unlock()

	if db.DB == nil {
		return fmt.Errorf("database is not open")
	}

	err := db.DB.Close()
	if err != nil {
		return err
	}

	db.DB = nil
	return nil
}

func (db *DB) IsOpen() bool {
	db.Lock()
	defer db.Unlock()

	return db.DB != nil
}

func (db *DB) IsTemporary() bool {
	db.Lock()
	defer db.Unlock()

	return db.isTempDB
}

func (db *DB) SetTemporary(temporary bool) {
	db.Lock()
	defer db.Unlock()

	db.isTempDB = temporary
}

func (db *DB) CustomOperation() {

}

var eventTypes = []string{"http", "dns", "rmi", "ldap"}

func (db *DB) listEvent(eventType string, lastID string, count int, action string) (ret []*Event, total int) {
	ret = []*Event{}
	err := db.View(func(tx *bbolt.Tx) error {
		bb := tx.Bucket([]byte("reverse_log"))
		if bb == nil {
			return nil
		}

		types := eventTypes
		if eventType != "" {
			types = []string{eventType}
		}

		var all []*Event
		for _, t := range types {
			eb := bb.Bucket([]byte(t))
			if eb == nil {
				continue
			}
			total += eb.Stats().KeyN

			var events []*Event
			cursor := eb.Cursor()

			if lastID == "" {
				if action == "Prev" {
					for k, v := cursor.First(); k != nil && len(events) < count; k, v = cursor.Next() {
						var e Event
						if json.Unmarshal(v, &e) == nil {
							events = append(events, &e)
						}
					}
				} else {
					for k, v := cursor.Last(); k != nil && len(events) < count; k, v = cursor.Prev() {
						var e Event
						if json.Unmarshal(v, &e) == nil {
							events = append(events, &e)
						}
					}
				}
			} else {
				key32, _ := strconv.Atoi(lastID)
				keyBytes := make([]byte, 8)
				binary.BigEndian.PutUint64(keyBytes, uint64(key32))
				k, _ := cursor.Seek(keyBytes)
				if k == nil {
					continue
				}
				if action == "Prev" {
					// Prev: get events with IDs smaller than lastID (earlier events)
					for k, v := cursor.Prev(); k != nil && len(events) < count; k, v = cursor.Prev() {
						var e Event
						if json.Unmarshal(v, &e) == nil {
							events = append(events, &e)
						}
					}
				} else {
					// Next: get events with IDs smaller than lastID (going backward in time)
					for k, v := cursor.Prev(); k != nil && len(events) < count; k, v = cursor.Prev() {
						var e Event
						if json.Unmarshal(v, &e) == nil {
							events = append(events, &e)
						}
					}
				}
			}
			all = append(all, events...)
		}

		if len(types) == 1 || len(all) <= count {
			ret = all
		} else {
			// Merge-sort by ID descending (newest first) and take top count
			sortEvents(all)
			if len(all) > count {
				all = all[:count]
			}
			ret = all
		}
		return nil
	})
	if err != nil {
		logger.Error(err.Error())
	}
	return
}

func sortEvents(events []*Event) {
	sort.Slice(events, func(i, j int) bool {
		return events[i].ID > events[j].ID
	})
}

type EventStats struct {
	HTTP  int `json:"http"`
	DNS   int `json:"dns"`
	RMI   int `json:"rmi"`
	LDAP  int `json:"ldap"`
	Total int `json:"total"`
}

func (db *DB) getEventStats() *EventStats {
	stats := &EventStats{}
	db.View(func(tx *bbolt.Tx) error {
		bb := tx.Bucket([]byte("reverse_log"))
		if bb == nil {
			return nil
		}
		for _, t := range eventTypes {
			if eb := bb.Bucket([]byte(t)); eb != nil {
				n := eb.Stats().KeyN
				switch t {
				case "http":
					stats.HTTP = n
				case "dns":
					stats.DNS = n
				case "rmi":
					stats.RMI = n
				case "ldap":
					stats.LDAP = n
				}
				stats.Total += n
			}
		}
		return nil
	})
	return stats
}

func (db *DB) storeEvent(ev *Event) {
	if err := db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("reverse_log"))
		if err != nil {
			logger.Fatal(err)
			return err
		}
		eb, err := b.CreateBucketIfNotExists([]byte(ev.EventType))
		if err != nil {
			logger.Fatal(err)
			return err
		}
		// 获取递增的int64键值
		key, err := eb.NextSequence()
		if err != nil {
			logger.Fatal(err)
			return err
		}
		keyBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(keyBytes, key)
		ev.ID = int64(key)
		if data, err := json.Marshal(ev); err == nil {
			if err := eb.Put(keyBytes, data); err != nil {
				return err
			}
		}
		mb, err := b.CreateBucketIfNotExists([]byte("meta"))
		db.incr(mb, []byte(fmt.Sprintf("count_%s", ev.EventType)))
		return nil
	}); err != nil {
		logger.Fatal(err)
	}

}

func (db *DB) setHTTPResponse(hrc *HTTPResponseConfig) {
	if err := db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("resp_config"))
		if err != nil {
			logger.Fatal(err)
			return err
		}
		hrcBucket, err := b.CreateBucketIfNotExists([]byte("http"))
		if err != nil {
			logger.Fatal(err)
			return err
		}
		data, _ := json.Marshal(hrc)
		hrcBucket.Put([]byte(hrc.GroupID), data)
		return nil
	}); err != nil {

	}
}

func (db *DB) getHTTPResponse(groupID string) (ret *HTTPResponseConfig) {
	err := db.View(func(tx *bbolt.Tx) error {
		if bb := tx.Bucket([]byte("resp_config")); bb != nil {
			if hrcBucket := bb.Bucket([]byte("http")); hrcBucket != nil {
				data := hrcBucket.Get([]byte(groupID))
				hrc := HTTPResponseConfig{}
				if json.Unmarshal(data, &hrc) == nil {
					ret = &hrc
				}
			}
		}
		return nil
	})
	if err != nil {
		logger.Error(err.Error())
	}
	return
}

func (db *DB) listHTTPResponses() (ret []*HTTPResponseConfig) {
	db.View(func(tx *bbolt.Tx) error {
		bb := tx.Bucket([]byte("resp_config"))
		if bb == nil {
			return nil
		}
		hrcBucket := bb.Bucket([]byte("http"))
		if hrcBucket == nil {
			return nil
		}
		hrcBucket.ForEach(func(k, v []byte) error {
			hrc := &HTTPResponseConfig{}
			if json.Unmarshal(v, hrc) == nil {
				ret = append(ret, hrc)
			}
			return nil
		})
		return nil
	})
	return
}

func (db *DB) deleteHTTPResponse(groupID string) {
	db.Update(func(tx *bbolt.Tx) error {
		bb := tx.Bucket([]byte("resp_config"))
		if bb == nil {
			return nil
		}
		hrcBucket := bb.Bucket([]byte("http"))
		if hrcBucket == nil {
			return nil
		}
		hrcBucket.Delete([]byte(groupID))
		return nil
	})
}

func (db *DB) setDNSResponse(drc *DNSResponseConfig) {
	if err := db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("resp_config"))
		if err != nil {
			logger.Fatal(err)
			return err
		}
		dnsBucket, err := b.CreateBucketIfNotExists([]byte("dns"))
		if err != nil {
			logger.Fatal(err)
			return err
		}
		data, _ := json.Marshal(drc)
		dnsBucket.Put([]byte(drc.GroupID), data)
		return nil
	}); err != nil {

	}

	return
}

func (db *DB) getDNSResponse(groupID string) (ret *DNSResponseConfig) {
	err := db.View(func(tx *bbolt.Tx) error {
		if bb := tx.Bucket([]byte("resp_config")); bb != nil {
			if dnsBucket := bb.Bucket([]byte("dns")); dnsBucket != nil {
				data := dnsBucket.Get([]byte(groupID))
				drc := DNSResponseConfig{}
				if json.Unmarshal(data, &drc) == nil {
					ret = &drc
				}
			}
		}
		return nil
	})
	if err != nil {
		logger.Error(err.Error())
	}
	return
}

func (db *DB) getInt(bucket *bbolt.Bucket, key []byte) int {
	v := bucket.Get(key)
	if v == nil {
		return 0
	}
	if ret, err := strconv.Atoi(string(v)); err == nil {
		return ret
	}
	return 0
}

func (db *DB) incr(bucket *bbolt.Bucket, key []byte) int {
	value := db.getInt(bucket, key)
	value += 1
	if err := bucket.Put(key, []byte(fmt.Sprintf("%d", value))); err != nil {
		logger.Fatal(err)
	}
	return value
}

func newDB() {

}
