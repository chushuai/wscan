/**
2 * @Author: shaochuyu
3 * @Date: 1/12/24
4 */

package thinkphp

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"
)

func extractValueFromURL(url string) (string, error) {
	// 正则表达式模式
	pattern := `(\d+)\*(\d+)`

	// 编译正则表达式
	re := regexp.MustCompile(pattern)

	// 查找匹配的字符串
	matches := re.FindStringSubmatch(url)

	// 提取值
	if len(matches) == 3 {
		i2, _ := strconv.Atoi(matches[1])
		i3, _ := strconv.Atoi(matches[2])
		fmt.Println(i2 * i3)
		return fmt.Sprintf("%d", i2*i3), nil
	} else {
		return "", fmt.Errorf("未找到匹配的值")
	}
}

func isRandomPhp(url string) bool {
	// 正则表达式模式
	pattern := `^/(\d+).php$`

	// 编译正则表达式
	re := regexp.MustCompile(pattern)

	return re.MatchString(url)
}

// /827327483.php
func TestExtractValueFromURL(t *testing.T) {
	// /index.php?s=/aa/bb/name/$%7B@printf(40179*41220)%7D
	url := "/index.php?s=/aa/bb/name/${@printf(43775*44642)}"
	fmt.Println(extractValueFromURL(url))

	fmt.Println(isRandomPhp("/x.php"))
	fmt.Println(isRandomPhp("/805483697.php"))
}
