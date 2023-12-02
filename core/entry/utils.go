/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package entry

import (
	"fmt"
	"os"
	"wscan/core/utils"
	"wscan/core/utils/log"
	"wscan/core/utils/printer"
)

func newJSONPrinter(file string) printer.Printer {
	if utils.FileExists(file) == true {
		log.Fatalf("FileExists %s", file)
	}
	// 打开要写入的文件
	fp, err := os.Create(file)
	if err != nil {
		fmt.Println("无法创建文件:", err)
		return nil
	}
	p := printer.NewJsonPrinter(fp)
	return p
}

func CompleteOutputPath() {
	utils.TimeStampSecond()
	utils.DatetimePretty()
}
