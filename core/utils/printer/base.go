/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package printer

import (
	"io"
	"sync"
)

type BasePrinter struct {
	sync.Mutex
	prefix             []byte
	suffix             []byte
	sep                []byte
	writerCloser       io.WriteCloser
	writeCloserCreator func() (io.WriteCloser, error)
	interceptor        []func(any) (any, error)
	convert            func(any) ([]byte, error)
}

type Printer interface {
	AddInterceptor(func(any) (any, error)) Printer
	Close() error
	Print(any) error
}

func (p *BasePrinter) AddInterceptor(interceptor func(any) (any, error)) Printer {
	p.interceptor = append(p.interceptor, interceptor)
	return p
}

func (p *BasePrinter) Close() error {
	p.Lock()
	defer p.Unlock()

	if p.writerCloser == nil {
		return nil
	}

	err := p.writerCloser.Close()
	if err != nil {
		return err
	}

	p.writerCloser = nil
	return nil
}

func (p *BasePrinter) Print(data any) error {
	p.Lock()
	defer p.Unlock()

	if p.writerCloser == nil {
		wc, err := p.writeCloserCreator()
		if err != nil {
			return err
		}
		p.writerCloser = wc
	}

	for _, interceptor := range p.interceptor {
		res, err := interceptor(data)
		if err != nil {
			return err
		}
		data = res
	}

	bytes, err := p.convert(data)
	if err != nil {
		return err
	}
	if bytes == nil {
		return nil
	}

	_, err = p.writerCloser.Write(bytes)
	if err != nil {
		return err
	}

	_, err = p.writerCloser.Write(p.sep)
	if err != nil {
		return err
	}

	return nil
}
