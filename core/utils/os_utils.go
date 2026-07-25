/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import (
	"math/rand"
	"net"
	"strconv"
	"time"
)

func GetRandomLocalAddr() (string, int, error) {
	// 创建一个随机端口号
	rand.Seed(time.Now().UnixNano())
	port := rand.Intn(65535-1024) + 1024

	// 尝试绑定到选定的端口
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		// 如果端口已经被占用，则递归调用该函数尝试选择另一个端口
		return GetRandomLocalAddr()
	}

	// 关闭监听器
	l.Close()

	// 返回本地回环地址和选定的端口号
	return "127.0.0.1", port, nil
}
