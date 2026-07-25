/**
2 * @Author: shaochuyu
3 * @Date: 12/22/23
4 */

package utils

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	logger "wscan/core/utils/log"
)

func APIProxy(targetURL *url.URL) http.Handler {
	// 创建反向代理
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// 设置自定义的Director函数
	proxy.Director = func(req *http.Request) {
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		req.Host = targetURL.Host
	}

	// 设置自定义的ModifyResponse函数
	proxy.ModifyResponse = func(response *http.Response) error {
		// 在这里记录请求和响应的内容

		logger.Printf("Response: %s %s %v\n", response.Status, response.Proto, response.Header)

		// 如果需要，可以读取和记录响应的内容
		responseBytes, err := io.ReadAll(response.Body)
		if err != nil {
			logger.Println("Error reading response body:", err)
		}
		logger.Println("Response Body:", string(responseBytes))
		logger.Info("-------------------------------")

		// 注意：修改了响应内容之后，需要重新设置响应的Body
		response.Body = io.NopCloser(bytes.NewBuffer(responseBytes))

		return nil
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Infof("%s %s, %v", r.Method, r.URL.String(), r.Header)
		if r.Body != nil {
			reqBytes, _ := io.ReadAll(r.Body)
			logger.Infof("Postdata: \n %s\n", string(reqBytes))
			r.Body = io.NopCloser(bytes.NewBuffer(reqBytes))
		}
		proxy.ServeHTTP(w, r)
	})
}
