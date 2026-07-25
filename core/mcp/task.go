/*
*
2 * @Author: shaochuyu
3 * @Date: 8/24/25
4
*/
package mcp

import (
	"errors"
	"fmt"
	"sync"
	"time"
	"wscan/core/model"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// TaskStatus 任务状态
type TaskStatus string

const (
	StatusCreated  TaskStatus = "created"  // 已创建，未开始
	StatusRunning  TaskStatus = "running"  // 正在运行
	StatusPaused   TaskStatus = "paused"   // 已暂停
	StatusStopped  TaskStatus = "stopped"  // 已停止
	StatusDeleted  TaskStatus = "deleted"  // 已删除
	StatusFailed   TaskStatus = "failed"   // 执行失败
	StatusFinished TaskStatus = "finished" // 正常完成
)

// TaskResult 任务执行结果
type TaskResult struct {
	Output    []*model.WebVuln `json:"output"`
	Err       string           `json:"error,omitempty"`
	StartTime time.Time        `json:"start_time"`
	EndTime   time.Time        `json:"end_time"`
}

// Task 任务实体
type Task struct {
	ID      string
	Name    string
	ScanUrl string
	Status  TaskStatus
	Result  *TaskResult
	RunFunc func(t *Task) error // 任务执行函数
	mu      sync.RWMutex        // 保护状态和结果
}

// TaskManager 任务管理器
type TaskManager struct {
	tasks map[string]*Task
	mu    sync.RWMutex
}

// NewTaskManager 创建任务管理器
func NewTaskManager() *TaskManager {
	return &TaskManager{
		tasks: make(map[string]*Task),
	}
}

// CreateTask 创建任务（不启动）
func (tm *TaskManager) CreateTask(name, scanUrl string, runFunc func(t *Task) error) *Task {
	task := &Task{
		ID:   primitive.NewObjectID().Hex(),
		Name: name,

		ScanUrl: scanUrl,
		Status:  StatusCreated,
		RunFunc: runFunc,
	}

	tm.mu.Lock()
	tm.tasks[task.ID] = task
	tm.mu.Unlock()

	return task
}

// GetTask 获取任务
func (tm *TaskManager) GetTask(id string) (*Task, bool) {
	tm.mu.RLock()
	task, exists := tm.tasks[id]
	tm.mu.RUnlock()
	return task, exists
}

// Start 启动任务
func (t *Task) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Status != StatusCreated && t.Status != StatusPaused && t.Status != StatusStopped {
		return fmt.Errorf("cannot start task in status: %s", t.Status)
	}

	t.Status = StatusRunning
	t.Result = &TaskResult{
		StartTime: time.Now(),
		// Output:    []*model.WebScanResult{},
	}

	// 模拟异步执行
	go func() {
		err := t.RunFunc(t)
		t.mu.Lock()
		defer t.mu.Unlock()

		if t.Status == StatusRunning { // 防止已被暂停或停止
			t.Result.EndTime = time.Now()
			if err != nil {
				t.Result.Err = err.Error()
				t.Status = StatusFailed
			} else {
				t.Status = StatusFinished
			}
		}
	}()

	return nil
}

// Pause 暂停任务（仅运行中可暂停）
func (t *Task) Pause() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Status != StatusRunning {
		return fmt.Errorf("only running task can be paused, current status: %s", t.Status)
	}

	t.Status = StatusPaused
	return nil
}

// Stop 停止任务（仅运行中可停止）
func (t *Task) Stop() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Status != StatusRunning {
		return fmt.Errorf("only running task can be stopped, current status: %s", t.Status)
	}

	t.Status = StatusStopped
	if t.Result != nil {
		t.Result.EndTime = time.Now()
	}
	return nil
}

// Resume 重新开始（仅暂停或停止可重新开始）
func (t *Task) Resume() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.Status != StatusPaused && t.Status != StatusStopped {
		return fmt.Errorf("only paused or stopped task can be resumed, current status: %s", t.Status)
	}

	return nil // 实际启动由 Start 触发
}

// Delete 删除任务（仅暂停或停止可删除）
func (tm *TaskManager) DeleteTask(id string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	task, exists := tm.tasks[id]
	if !exists {
		return errors.New("task not found")
	}

	task.mu.Lock()
	status := task.Status
	task.mu.Unlock()

	if status != StatusPaused && status != StatusStopped && status != StatusFinished && status != StatusFailed {
		return fmt.Errorf("only paused, stopped, finished, or failed tasks can be deleted, current status: %s", status)
	}

	delete(tm.tasks, id)
	return nil
}

// GetResult 获取任务结果
func (t *Task) GetResult() (*TaskResult, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.Result == nil {
		return nil, errors.New("task has not been executed yet")
	}
	return t.Result, nil
}

// Status 获取任务状态
func (t *Task) GetStatus() TaskStatus {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.Status
}
