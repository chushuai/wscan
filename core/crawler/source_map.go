/*
*
2 * @Author: shaochuyu
3 * @Date: 8/8/25
4
*/
package crawler

import (
	"encoding/json"
	"fmt"
)

type SourceMap struct {
	Version        int      `json:"version"`
	File           string   `json:"file,omitempty"`
	SourceRoot     string   `json:"sourceRoot,omitempty"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent,omitempty"`
	Names          []string `json:"names,omitempty"`
	Mappings       string   `json:"mappings"`
}

func ParseSourceMap(content string) (*SourceMap, error) {
	var smap SourceMap
	if err := json.Unmarshal([]byte(content), &smap); err != nil {
		return nil, fmt.Errorf("解析 Source Map JSON 失败: %w", err)
	}
	return &smap, nil
}
