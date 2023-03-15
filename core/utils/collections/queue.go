/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collections

import (
	"container/list"
	"sync"
)

type Queue struct {
	l *list.List
	m sync.RWMutex
}

func (q *Queue) Front() *list.Element {
	q.m.RLock()
	defer q.m.RUnlock()
	return q.l.Front()
}

func (q *Queue) Len() int {
	q.m.RLock()
	defer q.m.RUnlock()
	return q.l.Len()
}

func (q *Queue) PushBack(v interface{}) {
	q.m.Lock()
	defer q.m.Unlock()
	q.l.PushBack(v)
}

func (q *Queue) Remove(e *list.Element) {
	q.m.Lock()
	defer q.m.Unlock()
	q.l.Remove(e)
}

func (q *Queue) TryPop() interface{} {
	q.m.Lock()
	defer q.m.Unlock()
	if q.l.Len() == 0 {
		return nil
	}
	e := q.l.Front()
	q.l.Remove(e)
	return e.Value
}
