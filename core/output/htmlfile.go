/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package output

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"wscan/core/model"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
	"wscan/core/utils/printer"
)

type htmlFilePrinter struct {
	sync.Mutex
	filename       string
	rotateFilename string
	writer         *os.File
	writeCount     int
}

//go:embed "html_template.html"
var htmlTemplateData []byte

func (*htmlFilePrinter) AddInterceptor(func(interface{}) (interface{}, error)) printer.Printer {
	return nil
}
func (hfp *htmlFilePrinter) Close() error {
	return hfp.writer.Close()
}

func (hfp *htmlFilePrinter) LogSubdomain(interface{}) error {
	return nil
}
func (hfp *htmlFilePrinter) LogVuln(interface{}) error {
	return nil
}
func (hfp *htmlFilePrinter) Print(res interface{}) error {
	hfp.Lock()
	defer hfp.Unlock()
	switch res.(type) {
	case *model.Vuln:
		vuln := res.(*model.Vuln)
		webVuln := vuln.ToWebVuln()
		if data, err := json.Marshal(webVuln); err == nil {
			hfp.writer.Write([]byte("<script class='web-vulns'>webVulns.push("))
			hfp.writer.Write(data)
			hfp.writer.Write([]byte(")</script>\n"))
		}
	}
	return nil
}

func (hfp *htmlFilePrinter) writePrefix() error {
	return nil
}

func NewHTMLFilePrinter(filename string) *htmlFilePrinter {
	if utils.FileExists(filename) == true {
		logger.Fatalf("FileExists %s", filename)
	}
	// 打开要写入的文件
	fp, err := os.Create(filename)
	if err != nil {
		fmt.Println("无法创建文件:", err)
		return nil
	}
	fp.Write(htmlTemplateData)
	fp.Write([]byte("\n"))
	return &htmlFilePrinter{
		filename: filename,
		writer:   fp,
	}
}
