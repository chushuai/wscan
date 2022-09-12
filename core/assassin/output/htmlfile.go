/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package output

import (
	"os"
	"sync"
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
func (*htmlFilePrinter) Lock() {

}
func (*htmlFilePrinter) LogSubdomain(interface{}) error {
	return nil
}
func (*htmlFilePrinter) LogVuln(interface{}) error {
	return nil
}
func (*htmlFilePrinter) Print(interface{}) error {
	return nil
}
func (*htmlFilePrinter) Unlock() {

}
func (*htmlFilePrinter) lockSlow() {

}
func (*htmlFilePrinter) unlockSlow(int32) {

}
func (*htmlFilePrinter) writePrefix() error {
	return nil
}
