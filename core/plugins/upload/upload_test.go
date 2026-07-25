/**
2 * @Author: shaochuyu
3 * @Date: 12/31/23
4 */

package upload

import (
	"bytes"
	"context"
	"crypto/md5"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
	logger "wscan/core/utils/log"
)

var indexHtml = `<!DOCTYPE html>  
<html>  
<head>  
  <title>upload file</title>  
</head>  
<body>  
  <h1>upload file</h1>  
  <form action="/myfile" method="post" enctype="multipart/form-data">
    <input type="file" name="file">  <br>
    <input type="submit" value="upload">  <br>
  </form>  
</body>  
</html>`

var lastBody = []byte{}
var lastHash = ""
var lastHashPath = ""

// CalculateMD5Hash 计算给定字符串的MD5哈希值
func CalculateMD5Hash(input string) (string, error) {
	re := regexp.MustCompile(`md5\('([^']*)'\)`)
	match := re.FindStringSubmatch(input)
	if len(match) > 1 {
		parameter := match[1]
		hash := md5.Sum([]byte(parameter))
		logger.Infof("hash=%s", fmt.Sprintf("%x", hash))
		return fmt.Sprintf("%x", hash), nil
	} else {
		return "", fmt.Errorf("No match found")
	}
}

func uploadFile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "无效的请求方法", http.StatusMethodNotAllowed)
		logger.Infof("uploadFile 无效的请求方法, %s", r.URL.String())
		return
	}
	body, _ := io.ReadAll(r.Body)

	r.Body = io.NopCloser(bytes.NewReader(body))
	fmt.Println(">>>>>>>>>>>>>>>>>")
	fmt.Println(string(body))
	fmt.Println("<<<<<<<<<<<<<<<<<<")
	file, handler, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "没有找到文件", http.StatusBadRequest)
		return
	}
	defer file.Close()
	logger.Infof("uploadFile, %s", handler.Filename)
	filePath := fmt.Sprintf("webshell/%s", handler.Filename)
	outfile, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "无法创建文件", http.StatusInternalServerError)
		return
	}
	defer outfile.Close()

	lastBody, _ = io.ReadAll(file)

	_, err = io.Copy(outfile, bytes.NewReader(lastBody))
	if err != nil {
		http.Error(w, "无法复制文件内容", http.StatusInternalServerError)
		return
	}
	if lastHash == "" {
		if strmd5, err := CalculateMD5Hash(string(lastBody)); err == nil {
			lastHash = strmd5
			lastHashPath = handler.Filename
			logger.Infof("%s md5=%s", handler.Filename, strmd5)
		}

	}

	fmt.Fprintln(w, "文件上传成功")
}

// xray --log-level=debug ws  --plug upload  --basic http://localhost:8080/  --json-output=upload.json
func TestUpload(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/myfile", uploadFile)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		w.Header().Set("Content-Type", "text/html;charset=ISO-8859-1")
		logger.Info("+++++++++++++++++++++++==")
		logger.Infof("-->%s", r.URL.String())

		body, _ := io.ReadAll(r.Body)

		r.Body = io.NopCloser(bytes.NewReader(body))
		fmt.Println(body)

		if len(lastBody) > 0 {
			logger.Infof("lastBody\n %s", string(lastBody))
		}

		if len(lastHash) > 0 && strings.Contains(r.URL.String(), lastHashPath) {
			fmt.Fprint(w, lastHash)
			logger.Infof("%s ,lastHash=  %s", r.URL, string(lastHash))
		} else {
			// 发送响应体
			fmt.Fprint(w, indexHtml)
		}
	})

	// 启动HTTP服务器
	server := &http.Server{Addr: ":8081", Handler: mux}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Shutdown the server after a short period (this is a test, not a long-running server)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}

func TestCalculateMD5Hash(t *testing.T) {
	fmt.Println(CalculateMD5Hash("GIF89a<?php echo md5('kCTCVDtw'); ?>"))
}
