/*
*
2 * @Author: shaochuyu
3 * @Date: 12/30/25
4
*/
package mcp

import (
	"sync"
	"wscan/core/model"
	"wscan/core/utils/printer"
)

type mcpPrinter struct {
	printer.Printer
	mu       sync.Mutex
	lastStat *model.StatisticRecord
	task     *Task
}

func (*mcpPrinter) AddInterceptor(func(any) (any, error)) printer.Printer {
	return nil
}

func (p *mcpPrinter) Close() error {
	// return p.Printer.Close()
	return nil
}

func (p *mcpPrinter) Print(res any) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch res.(type) {
	case *model.Vuln:
		vuln := res.(*model.Vuln)
		p.task.Result.Output = append(p.task.Result.Output, vuln.ToWebVuln())
	}
	return nil
}
func (*mcpPrinter) interceptStat() {

}
func (*mcpPrinter) interceptSubdomain() {

}
func NewMcpPrinter(task *Task) *mcpPrinter {
	return &mcpPrinter{
		task: task,
	}
}
