/**
2 * @Author: shaochuyu
3 * @Date: 3/15/23
4 */

package collections

import (
	"container/list"
	"testing"
)

func TestQueue(t *testing.T) {
	// 创建一个新的队列
	q := Queue{l: list.New()}

	// 验证队列初始长度为0
	if q.Len() != 0 {
		t.Errorf("Expected length of 0, but got %d", q.Len())
	}

	// 添加元素到队列
	q.PushBack(1)
	q.PushBack(2)

	// 验证队列长度为2
	if q.Len() != 2 {
		t.Errorf("Expected length of 2, but got %d", q.Len())
	}

	// 验证队列的第一个元素是1
	front := q.Front().Value
	if front != 1 {
		t.Errorf("Expected front element to be 1, but got %d", front)
	}

	// 尝试弹出队列的第一个元素
	popped := q.TryPop()

	// 验证弹出的元素是1
	if popped != 1 {
		t.Errorf("Expected popped element to be 1, but got %d", popped)
	}

	// 验证队列长度为1
	if q.Len() != 1 {
		t.Errorf("Expected length of 1, but got %d", q.Len())
	}

	// 删除队列中的一个元素
	q.Remove(q.Front())

	// 验证队列长度为0
	if q.Len() != 0 {
		t.Errorf("Expected length of 0, but got %d", q.Len())
	}
}
