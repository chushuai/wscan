/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package printer

import (
	"encoding/json"
	"io"
)

type JsonPrinter struct {
	*BasePrinter
}

func (JsonPrinter) AddInterceptor(func(interface{}) (interface{}, error)) Printer {
	return nil
}
func (JsonPrinter) Close() error {
	return nil
}

func (p *JsonPrinter) Print(data interface{}) error {
	p.Lock()
	defer p.Unlock()

	formatted, err := p.convert(data)
	if err != nil {
		return err
	}

	_, err = p.writerCloser.Write(formatted)
	if err != nil {
		return err
	}

	_, err = p.writerCloser.Write(p.sep)
	if err != nil {
		return err
	}

	return nil
}

func (p *JsonPrinter) writeWithSync(data []byte) error {
	p.Lock()
	defer p.Unlock()

	_, err := p.writerCloser.Write(data)
	if err != nil {
		return err
	}

	//  err = p.writerCloser.Sync()
	if err != nil {
		return err
	}

	return nil
}

func NewJsonPrinter(w io.WriteCloser) *JsonPrinter {
	return &JsonPrinter{
		BasePrinter: &BasePrinter{
			writerCloser: w,
			convert: func(data interface{}) ([]byte, error) {
				return json.Marshal(data)
			},
			sep: []byte(",\n"),
		},
	}
}
