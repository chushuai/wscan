/**
2 * @Author: shaochuyu
3 * @Date: 9/29/23
4 */

package comparer

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"
	"wscan/core/http"
	"wscan/core/utils/comparer/htmlcompare"
	logger "wscan/core/utils/log"
)

const (
	methodSimilar = "similar"
	methodCode    = "code"
	methodTitle   = "title"
)

func Identify404(rawUrl string) (ok bool, method string, response2 *http.Response) {
	// call CompareResponse

	resp, err := request404(rawUrl)
	if err != nil {
		return
	}
	method, ok, methodResp := judeMethod(resp, rawUrl)

	if method == methodCode {
		return ok, method, nil
	} else {
		if method == methodSimilar {
			return ok, method, methodResp
		}
		return ok, method, nil
	}
}

func request404(rawUrl string) (response2 *http.Response, err error) {
	httpClient := http.NewClient()
	request, err := http.NewRequest("GET", rawUrl, nil)
	if err != nil {
		return
	}
	resp, err := httpClient.Respond(context.Background(), request)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func judeMethod(resp *http.Response, rawUrl string) (method string, ok bool, resp1 *http.Response) {
	ok, method = false, ""

	// 通过status_code 判断
	if resp.StatusCode == 404 {
		return methodCode, ok, nil
	} else if bodyTitle(resp) {
		// 通过title判断
		return methodTitle, true, nil
	}

	similar, similarResp, meth := isSimilar(resp, rawUrl)
	if similar {
		// 通过自定义随机生成404页面，比较两个网页相似度
		return meth, true, similarResp

	}
	return method, ok, nil
}

// title识别
func bodyTitle(resp *http.Response) (code bool) {
	//doc, err := goquery.NewDocumentFromReader(strings.NewReader(resp.Text))
	//if err != nil {
	//	return
	//}

	// 获取网页标题
	// title := doc.Find("title").Text()
	// 清理标题文本，去掉多余的空白字符
	// cleanedTitle := strings.Join(strings.Fields(title), " ")

	// isTitle := service_scan.IsInvalidTitle(cleanedTitle)

	return false
}

func htmlToString(resp *http.Response) (htmlString string) {
	// 读取响应的HTML内容
	htmlBytes, err := io.ReadAll(strings.NewReader(resp.Text))
	if err != nil {
		fmt.Println("读取HTML内容出错:", err)
		return
	}
	// 将HTML内容字节转换为字符串
	hs := string(htmlBytes)
	return hs
}

func isSimilar(urlResp1 *http.Response, rawUrl string) (s bool, resp *http.Response, similarMethod string) {
	//bad_responses := []int{301, 302, 400, 401, 403, 499, 501, 503}
	url2 := "/lowercheck"   // 不存在路径
	url3 := "/folder/check" // 构造目录生成
	_, err := url.Parse(rawUrl)
	if err != nil {
		logger.Error("Error parsing base URL:", err)
		return
	}
	url2 = rawUrl + url2
	url3 = rawUrl + url3
	urlResp2, _ := request404(url2)
	urlResp3, _ := request404(url3)

	// 判断生成的url2和url3返回为空
	if urlResp2 == nil || urlResp3 == nil {
		logger.Warningf("Failed while testing for 404 error message")
		return false, nil, ""
	}
	if urlResp2.StatusCode == 404 && urlResp3.StatusCode == 404 {
		return true, nil, methodCode
	} else if urlResp1.StatusCode != 404 && urlResp2.StatusCode != 404 {
		urlRespString1 := htmlToString(urlResp1)
		urlRespString2 := htmlToString(urlResp2)
		urlRespString3 := htmlToString(urlResp3)

		hp1 := htmlcompare.NewHTMLProcessorFromString(urlRespString1)
		hp2 := htmlcompare.NewHTMLProcessorFromString(urlRespString2)
		hp3 := htmlcompare.NewHTMLProcessorFromString(urlRespString3)

		similar1 := htmlcompare.CompareHTMLProcessors(hp1, hp2)
		similar2 := htmlcompare.CompareHTMLProcessors(hp1, hp3)
		averageSimilarity := (similar1 + similar2) / 2
		if averageSimilarity > 0.90 {
			return false, urlResp1, ""
		}
		return true, nil, methodSimilar
	}

	return false, nil, ""

}
