/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collector

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/xml"
	stdhttp "net/http"
	"strings"
	wscanhttp "wscan/core/http"
	"wscan/core/resource"
	"wscan/core/utils/log"

	"github.com/panjf2000/ants/v2"
)

// burpRequestWrapper 用于解析 <request base64="true">...</request>
type burpRequestWrapper struct {
	Base64  bool   `xml:"base64,attr"`
	Content []byte `xml:",chardata"`
}

// burpResponseWrapper 用于解析 <response base64="true">...</response>
type burpResponseWrapper struct {
	Base64  bool   `xml:"base64,attr"`
	Content []byte `xml:",chardata"`
}

// burpItemRaw 用于完整解析 Burp XML item（含 base64 属性）
type burpItemRaw struct {
	Time           string              `xml:"time"`
	URL            string              `xml:"url"`
	Host           string              `xml:"host"`
	Port           string              `xml:"port"`
	Protocol       string              `xml:"protocol"`
	Method         string              `xml:"method"`
	Path           string              `xml:"path"`
	Extension      string              `xml:"extension"`
	Request        burpRequestWrapper  `xml:"request"`
	Status         int                 `xml:"status"`
	ResponseLength int                 `xml:"responselength"`
	Mimetype       string              `xml:"mimetype"`
	Response       burpResponseWrapper `xml:"response"`
	Comment        string              `xml:"comment"`
}

// burpItemsRaw 完整解析 Burp XML
type burpItemsRaw struct {
	XMLName     xml.Name      `xml:"items"`
	BurpVersion string        `xml:"burpVersion,attr"`
	ExportTime  string        `xml:"exportTime,attr"`
	Items       []burpItemRaw `xml:"item"`
}

type burpCollector struct {
	client   *wscanhttp.Client
	opts     *wscanhttp.ClientOptions
	fileData []byte
	pool     *ants.Pool
}

func (bc *burpCollector) FitOut(ctx context.Context, targets []string) (chan resource.Resource, error) {
	out := make(chan resource.Resource, 100)

	// 解析 Burp XML
	var itemsRaw burpItemsRaw
	if err := xml.Unmarshal(bc.fileData, &itemsRaw); err != nil {
		log.Errorf("Failed to parse Burp XML: %v", err)
		close(out)
		return out, err
	}

	if len(itemsRaw.Items) == 0 {
		log.Warn("No items found in Burp file")
		close(out)
		return out, nil
	}

	log.Infof("Loaded %d requests from Burp file", len(itemsRaw.Items))

	go func() {
		defer close(out)

		for _, item := range itemsRaw.Items {
			// 解码 request/response 字段
			rawRequest := bc.decodeRequest(item.Request)
			rawResponse := bc.decodeResponse(item.Response)

			// 优先用 BuildFlow 从原始请求文本解析（同时有 request 和 response）
			if len(rawRequest) > 0 && len(rawResponse) > 0 {
				flow := wscanhttp.BuildFlow(string(rawRequest), string(rawResponse))
				if flow != nil {
					out <- flow
					continue
				}
			}

			// 尝试用 net/http.ReadRequest 解析原始请求
			if len(rawRequest) > 0 {
				hReq, err := stdhttp.ReadRequest(bufio.NewReader(strings.NewReader(string(rawRequest))))
				if err == nil {
					req, err := wscanhttp.RequestFromNetHttpRequert(hReq)
					if err == nil {
						bc.sendRequest(ctx, req, out)
						continue
					}
				}
			}

			// 回退：用 URL + Method 字段构建请求
			if item.URL != "" {
				method := item.Method
				if method == "" {
					method = "GET"
				}
				req, err := wscanhttp.NewRequest(method, item.URL, nil)
				if err != nil {
					log.Errorf("Failed to create request from Burp item URL %s: %v", item.URL, err)
					continue
				}
				bc.sendRequest(ctx, req, out)
			}
		}
	}()

	return out, nil
}

// decodeRequest 解码 Burp XML 中的 request 字段（可能 base64 编码）
func (bc *burpCollector) decodeRequest(rw burpRequestWrapper) []byte {
	if len(rw.Content) == 0 {
		return nil
	}
	if rw.Base64 {
		decoded, err := base64.StdEncoding.DecodeString(string(rw.Content))
		if err != nil {
			log.Warnf("Failed to base64 decode Burp request: %v", err)
			return rw.Content
		}
		return decoded
	}
	return rw.Content
}

// decodeResponse 解码 Burp XML 中的 response 字段（可能 base64 编码）
func (bc *burpCollector) decodeResponse(rw burpResponseWrapper) []byte {
	if len(rw.Content) == 0 {
		return nil
	}
	if rw.Base64 {
		decoded, err := base64.StdEncoding.DecodeString(string(rw.Content))
		if err != nil {
			log.Warnf("Failed to base64 decode Burp response: %v", err)
			return rw.Content
		}
		return decoded
	}
	return rw.Content
}

// sendRequest 发送请求并将结果写入输出 channel
func (bc *burpCollector) sendRequest(ctx context.Context, req *wscanhttp.Request, out chan resource.Resource) {
	// 设置自定义 headers
	for key, values := range bc.opts.Headers {
		if len(values) > 0 {
			req.Header.Set(key, values[0])
		}
	}
	for key, value := range bc.opts.DefaultHeaders {
		if _, exists := req.Header[key]; !exists {
			req.Header.Set(key, value)
		}
	}

	resp, err := bc.client.Respond(ctx, req)
	if err != nil {
		log.Error(err)
		return
	}
	out <- &wscanhttp.Flow{Request: req, Response: resp}
}

// ParseBurpXML 解析 Burp Suite 导出的 XML 文件内容
func ParseBurpXML(data []byte) (*burpItemsRaw, error) {
	var items burpItemsRaw
	if err := xml.Unmarshal(data, &items); err != nil {
		return nil, err
	}
	return &items, nil
}

func NewFromBurpFile(fileData []byte, opts *wscanhttp.ClientOptions) *burpCollector {
	bc := &burpCollector{}
	bc.client = wscanhttp.NewClientWithOptions(opts)
	bc.pool, _ = ants.NewPool(30)
	bc.opts = opts
	bc.fileData = fileData
	return bc
}
