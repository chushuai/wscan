/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package output

import (
	"fmt"
	"os"
	"sync"
	"wscan/core/model"
	"wscan/core/utils/printer"
)

type htmlFilePrinter struct {
	sync.Mutex
	filename       string
	rotateFilename string
	writer         *os.File
	writeCount     int
}

func (*htmlFilePrinter) AddInterceptor(func(interface{}) (interface{}, error)) printer.Printer {
	return nil
}
func (*htmlFilePrinter) Close() error {
	return nil
}

func (*htmlFilePrinter) LogSubdomain(interface{}) error {
	return nil
}
func (*htmlFilePrinter) LogVuln(interface{}) error {
	return nil
}
func (*htmlFilePrinter) Print(res interface{}) error {
	switch res.(type) {
	case **model.Vuln:
		fmt.Println("not support html")
	}
	return nil
}

func (*htmlFilePrinter) writePrefix() error {
	return nil
}

func NewHTMLFilePrinter() *htmlFilePrinter {
	return &htmlFilePrinter{}
}
