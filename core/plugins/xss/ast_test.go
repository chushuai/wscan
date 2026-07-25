/**
2 * @Author: shaochuyu
3 * @Date: 4/13/24
4 */

package xss

import (
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"strings"
	"testing"
	"wscan/core/http"
	"wscan/core/utils"
)

func TestAST(t *testing.T) {
	// Test the function
	input := "your_input_1"
	body := "<html><head><title>Your Title  <!-- 这是一个注释your_input_1 --></title></head><script>your_input_1</script><body><div>Hello, World!<div>xxxxcccc</div></div><input type='text' name='input_name' value='your_input'><script>alert('Hello');</script></body></html>"
	occurrences := SearchInputInResponse(input, body)
	for _, occurrence := range occurrences {
		fmt.Println("[+]", occurrence.Type, occurrence.Details["tagname"])
	}
}

func TestASTX(t *testing.T) {
	req, err := http.NewRequest("GET", "http://testphp.vulnweb.com/listproducts.php?artist=<ScRiPt>11111111111111111</sCrIpT>", nil)
	if err != nil {
		t.Error(err)
	}
	client := http.NewClient()
	res, err := client.DoRaw(req)
	if err != nil {
		t.Skipf("skipping: target unreachable: %v", err)
	}

	occurrences := SearchInputInResponse("11111111111111111", res.Text)
	for _, occurrence := range occurrences {
		fmt.Println(occurrence)
	}
}

func isKeyOnlyInHTMLAttribute(htmlStr, target string) bool {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlStr))
	if err != nil {
		fmt.Println("Error parsing HTML:", err)
		return false
	}

	found := false

	// Find all elements in the document
	doc.Find("*").Each(func(i int, s *goquery.Selection) {
		if _, exists := s.Attr(target); exists {
			found = true
		}
	})

	return found
}

func TestElement(t *testing.T) {
	html := `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>XSS Injection Demo</title>
</head>
<body>

<h1>XSS Injection Demo</h1>
<input type="hidden" name="langue" value="\"ozmhl=\"\"">
 
<a  dddddd="111">iiiii</a>
</body>
</html> 

	`

	locations := SearchInputInResponse("dddddd", html)

	if len(locations) == 0 {
		return
	}

	location := locations[len(locations)-1]
	if location.Type == "html" {
		if location.Details["tagname"] == "style" {

		} else {
			tagname := location.Details["tagname"]
			fmt.Println("tagname:", tagname)
			flag := utils.RandomStr(utils.AsciiDigits+"abcdef", 6)
			fmt.Println(fmt.Sprintf("</%s><%s>", tagname, flag))
			truePayload := fmt.Sprintf("</%s><%s>alert(1)</%s>", utils.RandomUpper(tagname.(string)), utils.RandomUpper("script"), utils.RandomUpper("script"))
			fmt.Println(truePayload)
		}
	}

	fmt.Println(isKeyOnlyInHTMLAttribute(html, "ozmhl"))
	//doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	//if err != nil {
	//	fmt.Println("Error parsing HTML:", err)
	//	return
	//}
	//
	//doc.Find("*").Each(func(index int, s *goquery.Selection) {
	//	tagName := s.Get(0).Data
	//	element := new(Element)
	//	element.node = s.Nodes[0]
	//	element.name = tagName
	//	element.attributes = make(map[string]string)
	//	for _, attr := range s.Nodes[0].Attr {
	//		element.attributes[attr.Key] = attr.Val
	//	}
	//	element.text = s.Text()
	//})
}
