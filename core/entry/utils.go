/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package entry

import (
	"os"
	"wscan/core/utils"
	"wscan/core/utils/log"
	"wscan/core/utils/printer"
)

func newJSONPrinter(file string, convert func(any) ([]byte, error)) printer.Printer {
	if utils.FileExists(file) {
		log.Fatalf("FileExists %s", file)
	}
	// 打开要写入的文件
	fp, err := os.Create(file)
	if err != nil {
		log.Fatalf("FileExists %s", err.Error())
		return nil
	}
	p := printer.NewJsonPrinter(fp, convert)
	return p
}

func CompleteOutputPath() {
	utils.TimeStampSecond()
	utils.DatetimePretty()
}
