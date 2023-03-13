/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package printer

import (
	"fmt"
	"io"
)

type TextPrinter struct {
	*BasePrinter
}

func NewTextPrinter1(writerCloser io.WriteCloser, writeCloserCreator func() (io.WriteCloser, error), prefix, suffix, sep []byte) *TextPrinter {
	return &TextPrinter{
		BasePrinter: &BasePrinter{
			prefix:             prefix,
			suffix:             suffix,
			sep:                sep,
			writerCloser:       writerCloser,
			writeCloserCreator: writeCloserCreator,
			interceptor:        make([]func(interface{}) (interface{}, error), 0),
			convert: func(data interface{}) ([]byte, error) {
				return []byte(fmt.Sprintf("%v", data)), nil
			},
		},
	}
}

func NewTextPrinter(w io.WriteCloser) *TextPrinter {
	return &TextPrinter{
		BasePrinter: &BasePrinter{
			writerCloser: w,
			convert: func(data interface{}) ([]byte, error) {
				str, ok := data.(string)
				if !ok {
					return nil, fmt.Errorf("input data is not a string")
				}
				return []byte(str), nil
			},
			sep: []byte("\n"),
		},
	}
}

func (p *TextPrinter) AddInterceptor(interceptor func(interface{}) (interface{}, error)) Printer {
	p.Lock()
	defer p.Unlock()

	p.interceptor = append(p.interceptor, interceptor)
	return p
}

func (p *TextPrinter) Print(data interface{}) error {
	p.Lock()
	defer p.Unlock()

	for _, interceptor := range p.interceptor {
		result, err := interceptor(data)
		if err != nil {
			return err
		}
		data = result
	}

	formatted, err := p.convert(data)
	if err != nil {
		return err
	}

	_, err = p.writerCloser.Write(p.prefix)
	if err != nil {
		return err
	}

	_, err = p.writerCloser.Write(formatted)
	if err != nil {
		return err
	}

	_, err = p.writerCloser.Write(p.suffix)
	if err != nil {
		return err
	}

	_, err = p.writerCloser.Write(p.sep)
	if err != nil {
		return err
	}

	return nil
}

func (p *TextPrinter) writeWithSync(data []byte) error {
	p.Lock()
	defer p.Unlock()

	_, err := p.writerCloser.Write(data)
	if err != nil {
		return err
	}

	// err = p.writerCloser.Sync()
	if err != nil {
		return err
	}

	return nil
}

func (p *TextPrinter) Close() error {
	err := p.writeWithSync([]byte{})
	if err != nil {
		return err
	}

	err = p.writerCloser.Close()
	if err != nil {
		return err
	}

	return nil
}
