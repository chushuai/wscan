/**
2 * @Author: shaochuyu
3 * @Date: 3/15/23
4 */

package utils

import (
	"fmt"
	"net"
	"strconv"
	"testing"
)

func TestGetRandomLocalAddr(t *testing.T) {
	ip, port, err := GetRandomLocalAddr()
	if err != nil {
		t.Errorf("GetRandomLocalAddr failed with error: %s", err)
	}
	fmt.Println(ip, port)
	// 确保IP地址是本地回环地址
	if !net.ParseIP(ip).IsLoopback() {
		t.Errorf("GetRandomLocalAddr returned non-loopback IP address: %s", ip)
	}

	// 确保端口号在有效范围内并且未被占用
	l, err := net.Listen("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		t.Errorf("GetRandomLocalAddr returned invalid port: %d (%s)", port, err)
	}
	l.Close()
}
