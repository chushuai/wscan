/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package printer

import (
	"sync"
)

type ConsolePrinter struct {
	sync.Mutex
	interceptor []func(interface{}) (interface{}, error)
}

func (*ConsolePrinter) AddInterceptor(func(interface{}) (interface{}, error)) Printer {

	return nil
}

func (*ConsolePrinter) Close() error {

	return nil
}

func (c *ConsolePrinter) Print(interface{}) error {
	return nil
}
