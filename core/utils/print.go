/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import (
	"fmt"
	"github.com/kataras/pio"
)

func ColorPrintln(s string) {
	fmt.Println(pio.Rich(s, pio.Blue))
}
