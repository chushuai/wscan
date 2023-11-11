/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package output

import (
	"fmt"
	"github.com/kataras/pio"
	"sync"
	"wscan/core/model"
	"wscan/core/utils/printer"
	"wscan/core/utils/printer/nice"
)

type stdoutPrinter struct {
	printer.Printer
	mu       sync.Mutex
	lastStat *model.StatisticRecord
}

func (*stdoutPrinter) AddInterceptor(func(interface{}) (interface{}, error)) printer.Printer {
	return nil
}
func (p *stdoutPrinter) Close() error {
	return p.Printer.Close()
}
func (p *stdoutPrinter) Print(res interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch res.(type) {
	case *model.Vuln:
		vuln := res.(*model.Vuln)
		nice.PioPrinter.Print(pio.Rich(vuln.String(), pio.Red))
	case *model.StatisticRecord:
		p.lastStat = res.(*model.StatisticRecord)
	default:
		nice.PioPrinter.Println(pio.Rich(fmt.Sprintf("%v", res), pio.Red))
	}
	return nil
}
func (*stdoutPrinter) interceptStat() {

}
func (*stdoutPrinter) interceptSubdomain() {

}
func NewStdoutPrinter() *stdoutPrinter {
	return &stdoutPrinter{}
}
