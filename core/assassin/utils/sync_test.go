/**
2 * @Author: shaochuyu
3 * @Date: 3/15/23
4 */

package utils

import (
	"sync"
	"testing"
)

func TestSizedWaitGroup(t *testing.T) {
	swg := NewSizedWaitGroup(2)

	// 并发执行 5 个任务
	for i := 0; i < 5; i++ {
		swg.Add()

		go func(i int) {
			defer swg.Done()

			// 模拟一些工作
			var wg sync.WaitGroup
			wg.Add(3)
			go func() {
				defer wg.Done()
				// 模拟一些计算密集型任务
			}()
			go func() {
				defer wg.Done()
				// 模拟一些 I/O 密集型任务
			}()
			go func() {
				defer wg.Done()
				// 模拟一些网络 I/O 密集型任务
			}()
			wg.Wait()
		}(i)
	}

	// 等待所有任务完成
	swg.Wait()

}
