/*
*
2 * @Author: shaochuyu
3 * @Date: 7/8/25
4
*/
package model

import "time"

type ScanJob struct {
	ID         string    `json:"id"`
	URL        string    `json:"url"`
	Options    []string  `json:"options,omitempty"` // 传入给 wscan 的自定义参数
	Status     string    `json:"status"`            // pending / running / done / error
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	ResultPath string    `json:"result_path,omitempty"` // JSON 或 HTML 扫描报告文件路径
	ErrMsg     string    `json:"err_msg,omitempty"`
}
