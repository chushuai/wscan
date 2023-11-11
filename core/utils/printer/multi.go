/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package printer

import (
	"fmt"
	"sync"
)

type MultiPrinter struct {
	sync.Mutex
	printers    []Printer
	interceptor []func(interface{}) (interface{}, error)
}

func (p *MultiPrinter) AddInterceptor(interceptor func(interface{}) (interface{}, error)) Printer {
	p.interceptor = append(p.interceptor, interceptor)
	return p
}
func (p *MultiPrinter) AddPrinters(printers []Printer) *MultiPrinter {
	p.printers = append(p.printers, printers...)
	return p
}

func (p *MultiPrinter) Close() error {
	var err error
	for _, printer := range p.printers {
		if cerr := printer.Close(); cerr != nil {
			err = cerr
		}
	}
	return err
}

func (p *MultiPrinter) Print(data interface{}) error {
	p.Lock()
	defer p.Unlock()

	for _, interceptor := range p.interceptor {
		newData, err := interceptor(data)
		if err != nil {
			return err
		}
		data = newData
	}

	var errs []error
	for _, printer := range p.printers {
		if err := printer.Print(data); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to print to %d printers: %v", len(errs), errs)
	}

	return nil
}

func NewMultiPrinter() *MultiPrinter {
	return &MultiPrinter{}
}
