/*
*
2 * @Author: shaochuyu
3 * @Date: 8/24/25
4
*/
package mcp

import (
	"fmt"
	"testing"
	"time"
	logger "wscan/core/utils/log"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

func TestTask(t *testing.T) {
	tm := NewTaskManager()
	// 创建任务
	task1 := tm.CreateTask(primitive.NewObjectID().Hex(), "计数任务", func(t *Task) error {
		time.Sleep(3 * time.Second)
		return nil
	})

	// 开始任务
	if err := task1.Start(); err != nil {
		logger.Fatal(err)
	}

	// 等待1秒后暂停
	time.Sleep(1 * time.Second)
	if err := task1.Pause(); err != nil {
		fmt.Println("暂停失败:", err)
	} else {
		fmt.Println("任务已暂停")
	}

	// 重新开始
	if err := task1.Resume(); err == nil {
		if err := task1.Start(); err != nil {
			fmt.Println("重新开始失败:", err)
		} else {
			fmt.Println("任务已重新开始")
		}
	}

	// 等待任务完成
	time.Sleep(5 * time.Second)

	// 获取结果
	result, err := task1.GetResult()
	if err != nil {
		fmt.Println("获取结果失败:", err)
	} else {
		// fmt.Printf("输出: %s\n", result.Output)
		fmt.Printf("耗时: %v\n", result.EndTime.Sub(result.StartTime))
	}

	// 删除任务
	if err := tm.DeleteTask("t1"); err != nil {
		fmt.Println("删除失败:", err)
	} else {
		fmt.Println("任务已删除")
	}
}
