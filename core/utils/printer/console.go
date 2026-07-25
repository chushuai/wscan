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
	interceptor []func(any) (any, error)
}

func (*ConsolePrinter) AddInterceptor(func(any) (any, error)) Printer {

	return nil
}

func (*ConsolePrinter) Close() error {

	return nil
}

func (c *ConsolePrinter) Print(any) error {
	return nil
}
