/**
2 * @Author: shaochuyu
3 * @Date: 12/12/22
4 */

package http

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"github.com/antchfx/xmlquery"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"reflect"
	"strings"
	"testing"
	"wscan/core/utils"
	"wscan/core/utils/jsonpath"
	logger "wscan/core/utils/log"
)

func TestRequest(t *testing.T) {
	logger.Info("Test request")
	url := "http://47.98.142.136:8901/timer/login/loginManage"
	postData := "userName=q&passWord=1"
	req, err := RequestFromRawURL(url)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(req)
	fmt.Println(url, postData)

}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

func TestMultipart(t *testing.T) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// 添加第一个字段
	field1Writer, _ := writer.CreateFormField("field1")
	field1Writer.Write([]byte("Test"))

	// 添加第二个字段
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition",
		fmt.Sprintf(`form-data; name="%s"; filename="%s"`, escapeQuotes("field2"), escapeQuotes("xxx.sh")))
	h.Set("Content-Type", "text/plain; charset=utf-7")
	field2Writer, _ := writer.CreatePart(h)
	field2Writer.Write([]byte("Knock knock."))
	fmt.Println("++++", writer.FormDataContentType())
	writer.Close()
	fmt.Println("------------")
	fmt.Print(string(body.Bytes()))
	fmt.Println("------------")

}

func TestMultipartReader(t *testing.T) {
	v := "multipart/form-data; boundary=boundary"

	d, params, err := mime.ParseMediaType(v)
	if err != nil {
		t.Error(err)
	}
	fmt.Println(d)
	boundary, ok := params["boundary"]
	if !ok {
		t.Error(http.ErrMissingBoundary.Error())
	}
	mr := multipart.NewReader(strings.NewReader(`--boundary
Content-disposition: form-data; name="field1"

Test
--boundary
Content-disposition: form-data; name="field2"
Content-Type: text/plain; charset=utf-7

Knock knock.
ddd
--boundary--`), boundary)
	f, err := mr.ReadForm(10)
	if err != nil {
		t.Error(err)
	}

	fmt.Println(f)
	for k, v := range f.Value {
		fmt.Println(k, v)
	}

	fmt.Println(boundary)
}

func TestMultipartReader2(t *testing.T) {
	ContentType := "multipart/form-data; bounxdary=boundary"
	boundary, err := utils.ExtractBoundaryFromContentType(ContentType)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(boundary)
	// 模拟包含multipart/form-data内容的请求
	requestBody := `--boundary
Content-disposition: form-data; name="field1"

Test
--boundary
Content-disposition: form-data; name="field2"
Content-Type: text/plain; charset=utf-7

Knock knock.
ddd
--boundary--`

	// 将请求体转换为字节数组
	body := bytes.NewReader([]byte(requestBody))

	// 创建一个multipart.Reader
	multipartReader := multipart.NewReader(body, "boundary")

	// 遍历所有multipart部分
	for {
		part, err := multipartReader.NextPart()
		if err != nil {
			break
		}

		// 处理每个部分
		// 在这里，你可以根据Content-Disposition等信息处理字段或文件
		// 这里只是简单打印内容
		buf := new(bytes.Buffer)
		buf.ReadFrom(part)
		fmt.Println("Part Content:", buf.String())
		fmt.Println("FileName-->", part.FileName())
		fmt.Println("FileName-->", part.FormName())
		// 关闭当前部分，准备处理下一个
		part.Close()
	}

}

func TestFuzzJsonMutate(t *testing.T) {
	body := `{
	"userIds": [
		"n1ddae22de4f74f8993e83c6"
	],
	"uGroupIds": [],
	"privilegeName": "READER",
	"resourceld": "p7a63bcf493fb49c4959633c",
	"resourceType": "data-source"
}
`
	req, err := NewRequest("POST", "http://127.0.0.1:8080/myfile", strings.NewReader(body))
	if err != nil {
		t.Error(err)
	}
	req.SetHeader("Content-Type", "application/json")
	req.doCache()
	for _, param := range req.ParamsQueryAndBody() {
		newReq := req.Mutate(&Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: "xx", Suffix: ""})
		fmt.Println("----------")
		fmt.Println(string(newReq.body))
	}

}

func TestFuzzPath(t *testing.T) {
	req, err := NewRequest("GET", "http://testphp.vulnweb.com/index.php", nil)
	if err != nil {
		t.Error(err)
	}
	req.doCache()
	for _, param := range req.ParamsPath() {
		newReq := req.Mutate(&Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: "xx", Suffix: ""})
		fmt.Println("----------")
		fmt.Println(string(newReq.Dump()))
	}
	// This test only validates mutation logic locally, no HTTP request is sent
}

func TestFuzzALLParams(t *testing.T) {
	req, err := NewRequest("GET", "https://sqli-labs.bachang.org/Less-1/", nil)
	if err != nil {
		t.Error(err)
	}
	req.doCache()
	for _, param := range req.ParamsAll() {
		newReq := req.Mutate(&Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: "paylaod", Suffix: ""})
		fmt.Println("----------")
		fmt.Println(string(newReq.Dump()))
	}
	// This test only validates mutation logic locally, no HTTP request is sent
}

func TestFuzzCookie(t *testing.T) {
	req, err := NewRequest("GET", "http://192.168.3.7:8787/user/cookie-id", nil)
	if err != nil {
		t.Error(err)
	}
	req.AddCookie(&http.Cookie{
		Name:  "ID",
		Value: "1",
	})
	req.doCache()
	for _, param := range req.ParamsCookie() {
		newReq := req.Mutate(&Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: "1 and 1=0 ;\nselect md5(2017),md5(2017) -- ", Suffix: ""})
		fmt.Println("----------")
		fmt.Println(string(newReq.Dump()))

		client := NewClient()

		res, err := client.DoRaw(newReq)
		if err != nil {
			t.Logf("client.DoRaw error (expected if target is unreachable): %v", err)
			continue
		}

		fmt.Println(res.Text)
		fmt.Println("--------------")
		fmt.Println(string(res.Dump()))
	}
}

func TestFuzzHeader(t *testing.T) {
	req, err := NewRequest("POST", "http://192.168.3.7:8787/visitor/reference", nil)
	if err != nil {
		t.Error(err)
	}
	req.SetHeader("Content-Type", "application/json")
	req.SetHeader("Referer", "http://192.168.3.7:8787/visitor/reference")
	req.doCache()
	for _, param := range req.ParamsHeader() {
		newReq := req.Mutate(&Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: "http://192.168.3.7:8787/visitor/referenceand ' and  1=0 union select md5(1983-11-17),md5(1983-11-17),md5(1983-11-17),md5(1983-11-17),md5(1983-11-17) -- ", Suffix: ""})
		fmt.Println("----------")
		fmt.Println(string(newReq.Dump()))

		client := NewClient()

		res, err := client.DoRaw(newReq)
		if err != nil {
			t.Logf("client.DoRaw error (expected if target is unreachable): %v", err)
			continue
		}

		fmt.Println(res.Text)
		fmt.Println("--------------")
		fmt.Println(string(res.Dump()))
	}
}

func TestFuzzXMLMutate(t *testing.T) {
	body := `<root><child>original value</child><child2>another value</child2><author>
        <firstName>F. Scott</firstName>
        <lastName>Fitzgerald</lastName>
      </author></root>`
	req, err := NewRequest("POST", "http://127.0.0.1:8080/myfile", strings.NewReader(body))
	if err != nil {
		t.Error(err)
	}
	req.SetHeader("Content-Type", "application/xml")
	req.doCache()
	for _, param := range req.ParamsQueryAndBody() {
		newReq := req.Mutate(&Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: "xx", Suffix: ""})
		fmt.Println("----------")
		fmt.Println(string(newReq.body))
	}
}

func TestMultipartMutate(t *testing.T) {
	body := `--40769a1552a14e1e5295000cda7c57d6a9f693b043693ebbf2b4d153820c
Content-Disposition: form-data; name="file"; filename="gzfkgmqa.txt"
Content-Type: text/plain; charset=utf-7

test
--40769a1552a14e1e5295000cda7c57d6a9f693b043693ebbf2b4d153820c--
`
	req, err := NewRequest("POST", "http://127.0.0.1:8080/myfile", strings.NewReader(body))
	if err != nil {
		t.Error(err)
	}
	req.SetHeader("Content-Type", "multipart/form-data; boundary=40769a1552a14e1e5295000cda7c57d6a9f693b043693ebbf2b4d153820c")
	req.doCache()
	for _, param := range req.ParamsQueryAndBody() {
		fmt.Println(param)
	}
}

func TestA(t *testing.T) {
	pwd_dict := map[string]string{
		"admin:123456:":     "YWRtaW46MTIzNDU2",
		"report:8Jg0SR8K50": "cmVwb3J0OjhKZzBTUjhLNTA=",
		"root:icatch99":     "cm9vdDppY2F0Y2g5OQ==",
		"ADMIN:1234":        "QURNSU46MTIzNA==",
		"ADMIN:jvc":         "QURNSU46anZj",
		"ADMIN:1111":        "QURNSU46MTExMQ==",
		"OPERATOR:jvc":      "T1BFUkFUT1I6anZj",
		"OPERATOR:2222":     "T1BFUkFUT1I6MjIyMg==",
		"GUEST:3333":        "R1VFU1Q6MzMzMw==",
		"USER01:3333":       "VVNFUjAxOjMzMzM=",
		"USER12:3333":       "VVNFUjEyOjMzMzM=",
	}

	fmt.Println(pwd_dict)

	usrPwdDict := []struct {
		usr string
		pwd string
	}{
		{"admin", "123456"},
		{"admin", "12345"},
	}
	for _, usrpwd := range usrPwdDict {
		fmt.Println(fmt.Sprintf("%s:%s", usrpwd.usr, usrpwd.pwd))
		base64UsrPwd := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", usrpwd.usr, usrpwd.pwd)))

		fmt.Println(fmt.Sprintf("%s:%s", usrpwd.usr, usrpwd.pwd), string(base64UsrPwd))
	}

}

// Generic XML node structure
type Node struct {
	XMLName xml.Name
	Content []byte `xml:",innerxml"`
	Nodes   []Node `xml:",any"`
}

func TestFuzzFuzzXMLWithRaw(t *testing.T) {
	rawBody := `<?xml version="1.0" encoding="UTF-8"?>
<library xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:noNamespaceSchemaLocation="library.xsd">
  <catalog>
    <book isbn="978-3-16-148410-0" language="en">
      <title><![CDATA[The Great Gatsby]]></title>
      <author>
        <firstName>F. Scott</firstName>
        <lastName>Fitzgerald</lastName>
      </author>
      <publisher name="Scribner" yearFounded="1846"/>
      <publishedDate>1925-04-10</publishedDate>
      <genres>
        <genre>Fiction</genre>
        <genre>Classic</genre>
      </genres>
      <synopsis><![CDATA[The story primarily concerns the young and mysterious millionaire Jay Gatsby and his quixotic passion and obsession with the beautiful former debutante Daisy Buchanan.]]></synopsis>
      <reviews>
        <review id="rev1">
          <user nickname="BookLover82" location="New York, USA" rating="5">
            <comment><![CDATA[A timeless piece of literature that explores themes of decadence, idealism, resistance to change, social upheaval, and excess, creating a portrait of the Jazz Age or the Roaring Twenties that has been described as a cautionary tale regarding the American Dream.]]></comment>
          </user>
        </review>
        <review id="rev2">
          <user nickname="NovelNerd" location="London, UK" rating="4">
            <comment><![CDATA[An intriguing look at the lives of the rich and famous in the 1920s, with Fitzgerald's sharp observations and poetic prose.]]></comment>
          </user>
        </review>
      </reviews>
    </book>
    <book isbn="978-0-14-143951-8" language="en">
      <title><![CDATA[Pride and Prejudice]]></title>
      <author>
        <firstName>Jane</firstName>
        <lastName>Austen</lastName>
      </author>
      <publisher name="Penguin Classics" yearFounded="1941"/>
      <publishedDate>1813-01-28</publishedDate>
      <genres>
        <genre>Romance</genre>
        <genre>Social commentary</genre>
      </genres>
      <synopsis><![CDATA[The novel follows the character development of Elizabeth Bennet, the dynamic protagonist, who learns about the repercussions of hasty judgments and comes to appreciate the difference between superficial goodness and actual goodness.]]></synopsis>
      <reviews>
        <review id="rev3">
          <user nickname="AustenAdmirer" location="Oxford, UK" rating="5">
            <comment><![CDATA[One of the most charming love stories in English literature, filled with humor, wit, and profound insight into human nature.]]></comment>
          </user>
        </review>
      </reviews>
    </book>
  </catalog>
</library>`
	rootNode, err := xmlquery.Parse(bytes.NewReader([]byte(rawBody)))
	if err != nil {
		t.Error(err)
	}
	xpaths := []string{}
	RecursiveXMLNode(rootNode, func(node *xmlquery.Node) {
		xpath := GetXpathFromNode(node)
		if node.Type != xmlquery.TextNode {
			xpaths = append(xpaths, xpath)
		}

		fmt.Println(node.Type == xmlquery.TextNode)
	})
	for _, xpath := range xpaths {
		nodes := xmlquery.Find(rootNode, xpath)
		for _, node := range nodes {
			fmt.Println(node.InnerText())
			value := ConvertValue(node.InnerText(), "xxxxxxxxxx")
			oldChild := node.FirstChild
			node.FirstChild = &xmlquery.Node{
				Data: value,
				Type: xmlquery.TextNode,
			}
			raw := rootNode.OutputXML(false)
			fmt.Println(xpath, raw)
			node.FirstChild = oldChild
			break
		}
	}

}

func isSlice(v any) bool {
	// 获取变量的类型
	t := reflect.TypeOf(v)

	// 检查类型是否为切片
	// 注意：reflect.Slice 返回一个表示切片类型的 Type，我们可以使用 t.Kind() == reflect.Slice 来判断
	return t.Kind() == reflect.Slice
}

func TestJsonPath(t *testing.T) {
	body := `
{
	"userIds": [
		"n1ddae22de4f74f8993e83c6"
	],
	"uGroupIds": [],
	"privilegeName": "READER",
	"resourceld": "p7a63bcf493fb49c4959633c",
	"resourceType": "data-source"
}
`
	var i any
	json.Unmarshal([]byte(body), &i)
	for _, j := range jsonpath.RecursiveDeepJsonPath(body) {
		result, _ := jsonpath.Read(i, j)
		raw := jsonpath.ReplaceString(body, j, "hacked")
		fmt.Println(j, result, reflect.TypeOf(result), isSlice(result), raw)
	}
}

func TestSanitizeHeaderValue(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"no invalid chars", "hello world", "hello world"},
		{"newline removed", "hello\nworld", "helloworld"},
		{"carriage return removed", "hello\rworld", "helloworld"},
		{"CRLF removed", "hello\r\nworld", "helloworld"},
		{"tab preserved", "hello\tworld", "hello\tworld"},
		{"space preserved", "hello world", "hello world"},
		{"DEL removed", "hello\x7fworld", "helloworld"},
		{"null byte removed", "hello\x00world", "helloworld"},
		{"cmd injection payload", "\nexpr 123 + 456\n", "expr 123 + 456"},
		{"echo payload", "\necho abc123\n", "echo abc123"},
		{"all invalid", "\n\r", ""},
		{"empty string", "", ""},
		{"only valid", "abc-123", "abc-123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeHeaderValue(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeHeaderValue(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestRequest_Mutate_Header_SanitizesControlChars(t *testing.T) {
	req, err := NewRequest("GET", "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.SetHeader("Referer", "http://example.com/")
	req.doCache()

	newReq := req.Mutate(&Parameter{
		Position: PositionHeader,
		Key:      "Referer",
		Value:    "\nexpr 123 + 456\n",
	})
	if newReq == nil {
		t.Fatal("Mutate() should return non-nil")
	}
	vals := newReq.Header["Referer"]
	if len(vals) == 0 {
		t.Fatal("Header should be set")
	}
	if vals[0] != "expr 123 + 456" {
		t.Errorf("Mutate(header) should sanitize control chars, got %q", vals[0])
	}
	if strings.ContainsAny(vals[0], "\n\r") {
		t.Errorf("Header value should not contain control chars, got %q", vals[0])
	}
}
