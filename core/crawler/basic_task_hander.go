/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package crawler

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"strings"
	"wscan/core/http"
	"wscan/core/utils"
	logger "wscan/core/utils/log"

	"github.com/PuerkitoBio/goquery"
)

func (c *Crawler) handleBasicTask(t *task) {

	// 发送 HTTP 请求
	resp, err := c.Client.DoRaw(t.req)
	if err != nil {
		// 处理错误
		c.handleErr(err)
		return
	}

	c.handleFlow(&http.Flow{
		Request:  t.req,
		Response: resp,
	})

	// 从当前URL路径中提取父目录，加入爬虫队列
	// 例如 /a/b/c.html 会发现 /a/ 和 /a/b/
	c.discoverParentDirs(t)

	// 处理30X跳转
	l, err := resp.NativeResponse.Location()
	if err == nil {
		// 构建新的请求对象
		req, err := http.NewRequest("GET", l.String(), nil)
		if err != nil {
			// 处理请求构建错误
			c.handleErr(err)
		}

		// 复制原请求对象的Header信息
		for k, v := range t.req.Header {
			req.Header[k] = v
		}
		if !c.handleReq(req) {

		}
		// 添加新的任务
		c.NewTask(req, t.depth+1)
	}

	// js 文件
	ext := t.req.GetURL().FileExt()
	if utils.StringIIn(ext, []string{"js", "map"}) {
		for _, r := range ParseResponseURL(t.req.GetURL().RawUrl(), string(resp.GetRawBody())) {
			c.NewTask(r, t.depth+1)
		}
	}
	if t.req.GetURL().Path == "/robots.txt" || t.req.GetURL().Path == "/sitemap.xml" {
		for _, r := range ParseResponseURL(t.req.GetURL().RawUrl(), string(resp.GetRawBody())) {
			c.NewTask(r, t.depth+1)

		}
		return
	}
	// Webpack 前端泄露

	// 处理响应的 HTML 文档
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.GetRawBody()))
	if err != nil {
		// 处理错误
		c.handleErr(err)
		return
	}
	u := t.req.GetURL()

	// 调用处理函数处理 HTML 文档
	c.handleDocument(u.RawUrl(), doc, resp, t.depth)

	// 判断是否需要继续遍历页面链接
	if t.depth < c.config.MaxDepth || c.config.MaxDepth == 0 {
		links := []string{} // ExtractLinks(resp.Body, t.req.URL)

		doc.Find("a").Each(func(i int, q *goquery.Selection) {
			href, exists := q.Attr("href")
			if exists {
				if newUrl, err := resp.GetURL().Parse(href); err == nil {
					links = append(links, newUrl.String())
				}
			}
		})
		doc.Find("script").Each(func(i int, q *goquery.Selection) {
			href, exists := q.Attr("src")
			if exists {
				if newUrl, err := resp.GetURL().Parse(href); err == nil {
					links = append(links, newUrl.String())
				}
			}
		})
		doc.Find("link").Each(func(i int, q *goquery.Selection) {
			href, exists := q.Attr("href")
			if exists {
				if newUrl, err := resp.GetURL().Parse(href); err == nil {
					links = append(links, newUrl.String())
				}
			}
		})
		for _, link := range links {
			// 构建新的请求对象
			req, err := http.NewRequest("GET", link, nil)
			if err != nil {
				// 处理请求构建错误
				c.handleErr(err)
				continue
			}
			// 复制原请求对象的Header信息
			for k, v := range t.req.Header {
				req.Header[k] = v
			}

			// 判断请求是否需要进一步处理
			skip := false
			if !c.handleReq(req) {
				skip = true
			}

			if skip {
				continue
			}

			// 添加新的任务
			c.NewTask(req, t.depth+1)
		}
		doc.Find("form").Each(func(i int, s *goquery.Selection) {
			// 提取表单动作
			formAction, _ := s.Attr("action")
			formEnctype, _ := s.Attr("enctype")
			if formEnctype != "" {
				logger.Infof("found form [POST] enctype: %s", formEnctype)
			}
			// 提取请求方法
			method, _ := s.Attr("method")
			if newUrl, err := resp.GetURL().Parse(formAction); err == nil {
				formData := url.Values{}
				multipartBody := &bytes.Buffer{}
				multipartWriter := multipart.NewWriter(multipartBody)
				// 提取表单字段
				s.Find("input, select, textarea").Each(func(j int, input *goquery.Selection) {
					// 提取字段名称
					fieldName, _ := input.Attr("name")
					// 提取字段类型
					fieldType, _ := input.Attr("type")

					if fieldType == "submit" {
						return
					}
					defaultValue, _ := input.Attr("value")
					if formEnctype == "multipart/form-data" {
						h := make(textproto.MIMEHeader)
						if fieldType == "file" {
							h.Set("Content-Disposition",
								fmt.Sprintf(`form-data; name="%s"; filename="%s"`, utils.EscapeQuotes(fieldName),
									utils.EscapeQuotes(fmt.Sprintf("%s.txt", utils.RandLetters(8)))))
							h.Set("Content-Type", "application/octet-stream")
						} else {
							h.Set("Content-Disposition",
								fmt.Sprintf(`form-data; name="%s"`, utils.EscapeQuotes(fieldName)))
						}
						fieldWriter, _ := multipartWriter.CreatePart(h)
						fieldWriter.Write([]byte("test"))
					} else {
						formData.Add(fieldName, defaultValue)
					}
					logger.Infof("[form] fieldName: %s; fieldType: %s; defaultValue: %s", fieldName, fieldType, defaultValue)
				})
				multipartWriter.Close()
				var req *http.Request
				if strings.ToUpper(method) == "POST" {
					if formEnctype == "multipart/form-data" {
						if req, err = http.NewRequest("POST", newUrl.String(), bytes.NewReader(multipartBody.Bytes())); err != nil {
							logger.Error(err)
							return
						}
						req.Header.Set("Content-Type", multipartWriter.FormDataContentType())
					} else {
						if req, err = http.NewRequest("POST", newUrl.String(), strings.NewReader(formData.Encode())); err != nil {
							logger.Error(err)
							return
						}
						req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					}

				} else {
					if formEnctype == "multipart/form-data" {
						if req, err = http.NewRequest("POST", newUrl.String(), bytes.NewReader(multipartBody.Bytes())); err != nil {
							logger.Error(err)
							return
						}
						req.Header.Set("Content-Type", multipartWriter.FormDataContentType())
					} else {
						getURL := newUrl.String() + "?" + formData.Encode()
						if req, err = http.NewRequest("GET", getURL, nil); err != nil {
							logger.Error(err)
							return
						}
					}
				}
				logger.Infof("found form url: %s action: %s; method: %s; formData: %s", newUrl.String(), formAction, method, formData.Encode())
				// 添加新的任务
				c.NewTask(req, t.depth+1)
			} else {
				logger.Error(err)
			}
		})

	}
}

func (*Crawler) do() {

}

// discoverParentDirs 从当前请求URL路径中提取所有父目录，作为新任务加入爬虫队列
// 例如 /a/b/c.html 会发现 /a/ 和 /a/b/
// 爬虫会自动发起真实请求，产生包含匹配Request和Response的完整Flow
func (c *Crawler) discoverParentDirs(t *task) {
	reqURL := t.req.GetURL()
	path := reqURL.Path
	if path == "" || path == "/" {
		return
	}
	// 去掉末尾的 / 以统一处理
	path = strings.TrimSuffix(path, "/")

	// 逐级提取父目录
	// /a/b/c.html → /a/b/ → /a/ → /
	for {
		lastSlash := strings.LastIndex(path, "/")
		if lastSlash < 0 {
			break
		}
		dirPath := path[:lastSlash+1] // 包含末尾的 /
		path = path[:lastSlash]       // 去掉最后一段，继续向上

		dirURL := fmt.Sprintf("%s://%s%s", reqURL.Scheme, reqURL.Host, dirPath)
		dirReq, err := http.NewRequest("GET", dirURL, nil)
		if err != nil {
			continue
		}
		// 继承原始请求的Header，保持Cookie等会话上下文
		for k, v := range t.req.Header {
			dirReq.Header[k] = v
		}
		c.NewTask(dirReq, t.depth+1)

		// lastSlash == 0 说明已经到达根目录 /，结束循环
		if lastSlash == 0 {
			break
		}
	}
}
