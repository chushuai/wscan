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

func (*stdoutPrinter) AddInterceptor(func(any) (any, error)) printer.Printer {
	return nil
}

func (p *stdoutPrinter) Close() error {
	// return p.Printer.Close()
	return nil
}

func (p *stdoutPrinter) Print(res any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch res.(type) {
	case *model.Vuln:
		vuln := res.(*model.Vuln)
		nice.PioPrinter.Print(pio.Rich(vuln.String(), pio.Red))
	case *model.StatisticRecord:
		lastStat := res.(*model.StatisticRecord)
		pending := lastStat.NumFoundUrls - lastStat.NumScannedUrls
		nice.PioPrinter.Println(pio.Rich(fmt.Sprintf("[*]  scanned: %d, pending: %d, requestSent: %d, latency: %fms, failedRatio: %f%%",
			lastStat.NumScannedUrls, pending,
			lastStat.NumSentHTTPRequests, lastStat.AverageResponseTime, lastStat.RatioFailedHTTPRequests), pio.Yellow))
		// 当 pending 从 >0 变为 0 且有扫描任务时，输出结束标志
		if pending == 0 && lastStat.NumFoundUrls > 0 &&
			(p.lastStat == nil || (p.lastStat.NumFoundUrls-p.lastStat.NumScannedUrls) > 0) {
			nice.PioPrinter.Println(pio.Rich("[*] All pending requests have been scanned", pio.Green))
		}
		p.lastStat = lastStat
	case *model.CrawlerResult:
		return nil
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
