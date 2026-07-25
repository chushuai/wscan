/*
*
2 * @Author: shaochuyu
3 * @Date: 12/9/22
4
*/
package crawler

import (
	"encoding/xml"
	"fmt"
	"net/url"

	"regexp"
	"strings"
	"wscan/core/http"
	logger "wscan/core/utils/log"
)

/*
*
从robots.txt文件中获取路径信息
*/
func extractPathsFromRobots(u *url.URL, body string) []*http.Request {
	logger.Info("starting to get paths from robots.txt.")
	var result []*http.Request
	var urlFindRegex = regexp.MustCompile(`(?:Disallow|Allow):.*?(/.+)`)
	var urlRegex = regexp.MustCompile(`(/.+)`)

	urlList := urlFindRegex.FindAllString(body, -1)
	for _, _url := range urlList {
		_url = strings.TrimSpace(_url)
		_url = urlRegex.FindString(_url)
		url, err := GetUrl(_url, *u)
		if err != nil {
			continue
		}
		req, _ := http.NewRequest(GET, url.String(), nil)
		// req.Source = config.FromRobots
		result = append(result, req)
	}
	return result
}

type sitemapStruct struct {
	URLs    []parsedURL `xml:"url"`
	Sitemap []parsedURL `xml:"sitemap"`
}

type parsedURL struct {
	Loc string `xml:"loc"`
}

// extractPathsFromSitemap
func extractPathsFromSitemap(u *url.URL, body string) []*http.Request {
	logger.Info("starting to get paths from robots.txt.")

	sitemap := sitemapStruct{}
	if err := xml.NewDecoder(strings.NewReader(body)).Decode(&sitemap); err != nil {
		return nil
	}

	var result []*http.Request
	for i, _ := range sitemap.URLs {
		_url := strings.TrimSpace(sitemap.URLs[i].Loc)
		url, err := GetUrl(_url, *u)
		if err != nil {
			continue
		}
		req, _ := http.NewRequest(GET, url.String(), nil)
		// req.Source = config.FromRobots
		result = append(result, req)
	}
	for i, _ := range sitemap.Sitemap {
		_url := strings.TrimSpace(sitemap.Sitemap[i].Loc)
		url, err := GetUrl(_url, *u)
		if err != nil {
			continue
		}
		req, _ := http.NewRequest(GET, url.String(), nil)
		// req.Source = config.FromRobots
		result = append(result, req)
	}
	return result
}

func extractSourceMapURL(jsData string) string {
	// 按行分割
	lines := strings.Split(jsData, "\n")
	if len(lines) == 0 {
		return ""
	}

	// 获取最后一行并去除首尾空格
	lastLine := strings.TrimSpace(lines[len(lines)-1])

	// 编译正则表达式：/\//#\s*sourceMappingURL=(.*)
	// 注意：Go 中的正则语法与 Python 基本一致，但字符串要双反斜杠转义
	regex := `^//\s*#\s*sourceMappingURL=(.*)$`
	re := regexp.MustCompile(regex)

	// 查找匹配
	matches := re.FindStringSubmatch(lastLine)
	if len(matches) >= 2 {
		return strings.TrimSpace(matches[1])
	}

	return ""
}

func AddRequestFromUrl(u *url.URL, path string, ret []*http.Request) []*http.Request {
	if newUrl, err := u.Parse(path); err == nil {
		if newReq, err := http.NewRequest(GET, newUrl.String(), nil); err == nil {
			ret = append(ret, newReq)
		}
	} else {
		logger.Error("url parse error: ", path)
	}

	return ret
}

func ParseResponseURL(u *url.URL, resStr string) (ret []*http.Request) {
	urlRegex := regexp.MustCompile(SuspectURLRegex)
	urlList := urlRegex.FindAllString(resStr, -1)
	fileName := UrlFileName(u)
	ext := UrlFileExt(u)
	if fileName == "robots.txt" {
		ret = extractPathsFromRobots(u, resStr)
	} else if fileName == "sitemap.xml" {
		ret = extractPathsFromSitemap(u, resStr)
	} else if ext == "js" {
		pattern := regexp.MustCompile(`^main\.[a-zA-Z0-9]+\.js$`)
		if pattern.MatchString(fileName) {
			ret = AddRequestFromUrl(u, fmt.Sprintf("%s.map", fileName), ret)
		}
		if path := extractSourceMapURL(resStr); path != "" {
			ret = AddRequestFromUrl(u, path, ret)
		}
		for _, url := range urlList {
			url = url[1 : len(url)-1]
			urlLower := strings.ToLower(url)
			if strings.HasPrefix(urlLower, "image/") ||
				strings.HasPrefix(urlLower, "text/") {
				continue
			}
			ret = AddRequestFromUrl(u, url, ret)
		}
	} else if ext == "map" {
		urlRegex = regexp.MustCompile(SuspectURLRegex)
		urlList = urlRegex.FindAllString(resStr, -1)
		if sm, err := ParseSourceMap(resStr); err == nil {
			for _, sourcesContent := range sm.SourcesContent {
				urlList = urlRegex.FindAllString(sourcesContent, -1)
				for _, url := range urlList {
					url = url[1 : len(url)-1]
					urlLower := strings.ToLower(url)
					if strings.HasPrefix(urlLower, "image/") ||
						strings.HasPrefix(urlLower, "text/") {
						continue
					}
					ret = AddRequestFromUrl(u, url, ret)
				}
			}
		}

	} else {
		for _, url := range urlList {
			url = url[1 : len(url)-1]
			urlLower := strings.ToLower(url)
			if strings.HasPrefix(urlLower, "image/") ||
				strings.HasPrefix(urlLower, "text/") {
				continue
			}
			ret = AddRequestFromUrl(u, url, ret)
		}
	}

	return
}
