/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package output

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
	"wscan/core/model"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
	"wscan/core/utils/printer"
)

type htmlFilePrinter struct {
	sync.Mutex
	filename       string
	rotateFilename string
	writer         *os.File
	writeCount     int
	startTime      time.Time
	lastStat       *model.StatisticRecord
	vulnCount      int
}

//go:embed "html_template.html"
var htmlTemplateData []byte

// GetHTMLTemplate returns the embedded HTML template bytes for external use.
func GetHTMLTemplate() []byte {
	return htmlTemplateData
}

func (*htmlFilePrinter) AddInterceptor(func(any) (any, error)) printer.Printer {
	return nil
}

func (hfp *htmlFilePrinter) Close() error {
	hfp.writeScanSummary()
	return hfp.writer.Close()
}

func (hfp *htmlFilePrinter) LogSubdomain(any) error {
	return nil
}
func (hfp *htmlFilePrinter) LogVuln(any) error {
	return nil
}

func (hfp *htmlFilePrinter) Print(res any) error {
	hfp.Lock()
	defer hfp.Unlock()
	switch res.(type) {
	case *model.Vuln:
		vuln := res.(*model.Vuln)
		webVuln := vuln.ToWebVuln()
		if data, err := json.Marshal(webVuln); err == nil {
			hfp.writer.Write([]byte("<script class='web-vulns'>webVulns.push("))
			hfp.writer.Write(data)
			hfp.writer.Write([]byte(")</script>\n"))
			hfp.vulnCount++
		}
	case *model.StatisticRecord:
		stat := res.(*model.StatisticRecord)
		hfp.lastStat = stat
	}
	return nil
}

func (hfp *htmlFilePrinter) writePrefix() error {
	return nil
}

func (hfp *htmlFilePrinter) writeScanSummary() {
	s := hfp.lastStat
	if s == nil {
		s = &model.StatisticRecord{}
	}
	duration := time.Since(hfp.startTime)
	summary := map[string]any{
		"found_urls":   s.NumFoundUrls,
		"scanned_urls": s.NumScannedUrls,
		"requests":     s.NumSentHTTPRequests,
		"vuln_count":   hfp.vulnCount,
		"start_time":   hfp.startTime.Format("2006-01-02 15:04:05"),
		"end_time":     time.Now().Format("2006-01-02 15:04:05"),
		"duration":     fmt.Sprintf("%.0f", duration.Seconds()),
		"avg_latency":  fmt.Sprintf("%.0f", s.AverageResponseTime),
	}
	data, _ := json.Marshal(summary)
	hfp.writer.Write([]byte("<script class='scan-summary'>scanSummary="))
	hfp.writer.Write(data)
	hfp.writer.Write([]byte("</script>\n"))
}

func NewHTMLFilePrinter(filename string) *htmlFilePrinter {
	if utils.FileExists(filename) {
		logger.Fatalf("FileExists %s", filename)
	}
	fp, err := os.Create(filename)
	if err != nil {
		fmt.Println("无法创建文件:", err)
		return nil
	}
	fp.Write(htmlTemplateData)
	fp.Write([]byte("\n"))
	return &htmlFilePrinter{
		filename:  filename,
		writer:    fp,
		startTime: time.Now(),
	}
}
