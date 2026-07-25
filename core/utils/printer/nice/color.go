/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package nice

import (
	"github.com/kataras/pio"
	"os"
)

type Color struct {
	raw        any
	color      int
	background bool
}

func (C *Color) Print() {
}

func (c *Color) Println() {

}

func (c *Color) Raw() any {
	return c.raw
}

func (c *Color) String() string {
	return pio.Rich("this is a blue text", c.color)

}

type Format interface {
	Raw() any
}

var PioPrinter *pio.Printer

func init() {
	PioPrinter = pio.NewTextPrinter("color", os.Stdout)
}
