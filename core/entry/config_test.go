/**
2 * @Author: shaochuyu
3 * @Date: 9/10/22
4 */

package entry

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"testing"
	"wscan/core/output"
	"wscan/core/utils/printer"
)

func TestConfig(t *testing.T) {
	config := NewExampleConfig()
	d, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("error: %v", err)
		return
	}

	fmt.Printf("dump:\n%s\n\n", string(d))
}

func TestMultiPrinter(t *testing.T) {
	printers := []printer.Printer{}
	printers = append(printers, output.NewStdoutPrinter())
	multiPrinter := printer.NewMultiPrinter()
	multiPrinter.AddPrinters(printers)
	multiPrinter.Print("hi printer")
}
