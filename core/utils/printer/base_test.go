/**
2 * @Author: shaochuyu
3 * @Date: 9/11/22
4 */

package printer

import (
	"fmt"
	"github.com/kataras/pio"
	"os"
	"testing"
	"time"
)

func TestPio(t *testing.T) {
	p := pio.NewTextPrinter("color", os.Stdout)
	p.Println(pio.Rich("this is a blue text", pio.Blue))
	p.Println(pio.Rich("this is a gray text", pio.Gray))
	p.Println(pio.Rich("this is a red text", pio.Red))
	p.Println(pio.Rich("this is a purple text", pio.Magenta))
	p.Println(pio.Rich("this is a yellow text", pio.Yellow))
	p.Println(pio.Rich("this is a green text", pio.Green))
}

func TestPioDefault(t *testing.T) {
	type message struct {
		Datetime string `xml:"Date"`
		Message  string `xml:"Message"`
	}
	p := pio.NewPrinter("default2", os.Stdout).WithMarshalers(pio.Text, pio.XMLIndent)
	p.Handle(func(result pio.PrintResult) {
		if result.IsOK() {
			fmt.Printf("original value was: %#v\n", result.Value)
		}
	})
	pio.RegisterPrinter(p) // or just use the p.Println...
	pio.Println(message{
		Datetime: time.Now().Format("2006/01/02 - 15:04:05"),
		Message:  "this is an xml message",
	})
	pio.Println("this is a normal text")
}

func TestPioHijack(t *testing.T) {
	pio.Register("default", os.Stdout).Marshal(pio.Text).Hijack(func(ctx *pio.Ctx) {
		if _, ok := ctx.Value.(int); ok {
			ctx.Cancel()
			return
		}
	})

	// this should not:
	pio.Print(42)

	pio.Print("this should be the only printed")

	// this should not:
	pio.Print(93)
}

func printWith(printerName string, marshaler pio.Marshaler) {
	type message struct {
		From string `json:"printer_name"`
		// fields should be exported, as you already know.
		Order    int    `json:"order"`
		Datetime string `json:"date"`
		Message  string `json:"message"`
	}
	p := pio.NewPrinter(printerName, os.Stderr).
		Marshal(marshaler)

	p.Println(message{
		From:     printerName,
		Order:    1,
		Datetime: time.Now().Format("2006/01/02 - 15:04:05"),
		Message:  "This is our structed error log message",
	})

	p.Println(message{
		From:     printerName,
		Order:    2,
		Datetime: time.Now().Format("2006/01/02 - 15:04:05"),
		Message:  "This is our second structed error log message",
	})
}

func Test1(t *testing.T) {
	fmt.Println(pio.Rich("xxxx", pio.Blue))
	// showcase json
	println("-----------")
	printWith("json1", pio.JSONIndent)

	// showcase xml
	println("-----------")
	printWith("xml", pio.XMLIndent)

	// show case text
	println("-----------")
	pio.Register("text", os.Stderr).Marshal(pio.Text)
	pio.Println("this is a text message, from text printer that has been registered inline")

	print("-----------")
}

func Test2(t *testing.T) {

}
