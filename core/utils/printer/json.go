/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package printer

import (
	"encoding/json"
	"io"
	"wscan/core/model"
	logger "wscan/core/utils/log"
)

type JsonPrinter struct {
	*BasePrinter
}

func (p *JsonPrinter) AddInterceptor(func(interface{}) (interface{}, error)) Printer {
	return nil
}
func (p *JsonPrinter) Close() error {
	return p.writerCloser.Close()
}

func (p *JsonPrinter) Print(res interface{}) error {
	p.Lock()
	defer p.Unlock()

	switch res.(type) {
	case *model.Vuln:
		vuln := res.(*model.Vuln)
		webVuln := model.WebVuln{
			Plugin: vuln.Binding.Plugin,
			Detail: model.VulnDetail{
				Addr:    vuln.TargetURL().String(),
				Payload: vuln.Payload,
				Extra:   vuln.Extra,
			},
			Target: model.WebTarget{
				URL: vuln.TargetURL().String(),
			},
		}
		if vuln.Param != nil {
			webVuln.Target.Params = []model.ParamInfo{
				{Position: vuln.Param.Position, Path: []string{vuln.Param.Key}},
			}
		}
		for _, flow := range vuln.Flow {
			webVuln.Detail.SnapShot = append(webVuln.Detail.SnapShot, flow.Response.Text)
		}
		formatted, err := p.convert(webVuln)
		if err != nil {
			logger.Error(err)
		}
		_, err = p.writerCloser.Write(formatted)
		if err != nil {
			return err
		}
		_, err = p.writerCloser.Write(p.sep)
		if err != nil {
			return err
		}
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
			sep: []byte("\n"),
		},
	}
}
