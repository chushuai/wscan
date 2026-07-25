/**
2 * @Author: shaochuyu
3 * @Date: 11/18/23
4 */

package crawler

import (
	"fmt"
	"net/http"
	"testing"
	"wscan/core/utils/log"

	"github.com/PuerkitoBio/goquery"
)

func TestSplider(t *testing.T) {
	// 指定要爬取的网址
	url := "http://mail.ldgzt.com"

	// 发起 HTTP 请求获取 HTML 内容
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	// 使用 goquery 解析 HTML
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	// 提取连接
	fmt.Println("链接:")
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		link, exists := s.Attr("href")
		if exists {
			fmt.Println(link)
		}
	})

	// 提取表单
	fmt.Println("\n表单:")
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		// 提取表单动作
		formAction, exists := s.Attr("action")
		if exists {
			fmt.Println("表单动作:", formAction)
		}

		// 提取请求方法
		method, exists := s.Attr("method")
		if exists {
			fmt.Println("请求方法:", method)
		}

		// 提取表单字段
		s.Find("input, select, textarea").Each(func(j int, input *goquery.Selection) {
			// 提取字段名称
			name, exists := input.Attr("name")
			if exists {
				fmt.Println("字段名称:", name)
			}

			// 提取字段类型
			fieldType, exists := input.Attr("type")
			if exists {
				fmt.Println("字段类型:", fieldType)
			}

			// 提取默认值
			defaultValue, exists := input.Attr("value")
			if exists {
				fmt.Println("默认值:", defaultValue)
			}

			// 可能还有其他属性需要提取，根据需要添加

		})
	})
}
