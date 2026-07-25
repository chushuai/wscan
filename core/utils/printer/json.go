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

func NewJsonPrinter(w io.WriteCloser, convert func(any) ([]byte, error)) *JsonPrinter {
	if convert == nil {
		convert = func(data any) ([]byte, error) {
			return json.Marshal(data)
		}
	}
	return &JsonPrinter{
		BasePrinter: &BasePrinter{
			writerCloser: w,
			convert:      convert,
			sep:          []byte("\n"),
		},
	}
}
