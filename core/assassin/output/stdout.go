/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package output

import (
	"sync"
	"wscan/core/assassin/model"
	"wscan/core/utils/printer"
)

type stdoutPrinter struct {
	printer.Printer
	mu       sync.Mutex
	lastStat *model.StatisticRecord
}

func (*stdoutPrinter) AddInterceptor(func(interface{}) (interface{}, error)) printer.Printer {
	return nil
}
func (*stdoutPrinter) Close() error {
	return nil
}
func (*stdoutPrinter) Print(interface{}) error {
	return nil
}
func (*stdoutPrinter) interceptStat() {

}
func (*stdoutPrinter) interceptSubdomain() {

}
