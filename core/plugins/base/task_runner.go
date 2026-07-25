/*
*
2 * @Author: shaochuyu
3 * @Date: 5/24/26
4
*/
package base

import (
	"fmt"
	"sync"
	"sync/atomic"
	"wscan/core/utils/collections"
	logger "wscan/core/utils/log"
)

// PoolSubmitter 匹配 ants.Pool 的 Submit 方法，结构性满足，无需直接依赖 ants
type PoolSubmitter interface {
	Submit(func()) error
}

// AsyncTask 插件提交的异步任务
type AsyncTask struct {
	Name string
	Fn   func()
}

// TaskRunner 异步任务调度器
type TaskRunner struct {
	pool   PoolSubmitter
	queue  *collections.Queue
	mu     sync.Mutex
	cond   *sync.Cond
	wg     sync.WaitGroup
	closed int32 // atomic, WaitAll 时设 1
	once   sync.Once
}

func NewTaskRunner(pool PoolSubmitter) *TaskRunner {
	tr := &TaskRunner{
		pool:  pool,
		queue: collections.NewQueue(),
	}
	tr.cond = sync.NewCond(&tr.mu)
	tr.startDrain()
	return tr
}

// startDrain 启动 drain goroutine，从队列取任务提交到 pool
func (tr *TaskRunner) startDrain() {
	tr.once.Do(func() {
		go func() {
			for {
				// 加锁检查队列
				tr.mu.Lock()
				for tr.queue.Len() == 0 && atomic.LoadInt32(&tr.closed) == 0 {
					tr.cond.Wait() // 等待 SubmitTask 唤醒
				}
				// 取出所有待处理任务
				var tasks []AsyncTask
				for {
					v := tr.queue.TryPop()
					if v == nil {
						break
					}
					tasks = append(tasks, v.(AsyncTask))
				}
				tr.mu.Unlock()

				// 如果已关闭且队列为空，退出
				if len(tasks) == 0 && atomic.LoadInt32(&tr.closed) == 1 {
					return
				}

				// 提交任务到 pool
				for _, task := range tasks {
					tr.wg.Add(1)
					fn := task.Fn
					err := tr.pool.Submit(func() {
						defer tr.wg.Done()
						fn()
					})
					if err != nil {
						tr.wg.Done()
						logger.Debugf("TaskRunner: pool submit failed for %q: %v", task.Name, err)
					}
				}
			}
		}()
	})
}

// SubmitTask 非阻塞提交任务到队列
func (tr *TaskRunner) SubmitTask(task AsyncTask) error {
	if atomic.LoadInt32(&tr.closed) == 1 {
		return fmt.Errorf("TaskRunner is closed, rejected task %q", task.Name)
	}
	tr.mu.Lock()
	tr.queue.PushBack(task)
	tr.mu.Unlock()
	tr.cond.Signal() // 唤醒 drain goroutine
	return nil
}

// WaitAll 关闭队列，等待所有任务完成
func (tr *TaskRunner) WaitAll() {
	atomic.StoreInt32(&tr.closed, 1)
	tr.cond.Signal() // 唤醒 drain goroutine 使其退出
	tr.wg.Wait()
}
