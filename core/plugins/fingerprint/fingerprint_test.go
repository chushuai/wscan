/**
2 * @Author: shaochuyu
3 * @Date: 4/4/24
4 */

package fingerprint

import (
	"fmt"
	"path/filepath"
	"testing"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

func TestFp(t *testing.T) {
	pocPaths := []string{}
	for _, include := range []string{"/home/cy/cert_work_python/wscan/core/plugins/fingerprint/technologies/*"} {
		if pocFiles, err := filepath.Glob(include); err == nil {
			for _, d := range pocFiles {
				if utils.IsDir(d) {
					if files, err := utils.GetAllFiles(d); err == nil {
						pocPaths = append(pocPaths, files...)
					}
				} else {
					pocPaths = append(pocPaths, d)
				}
			}
		} else {
			logger.Errorf("Path glob match error: " + err.Error())
		}
	}
	for _, ppocPath := range pocPaths {
		if template, err := LoadNucleiYamlPOC(ppocPath); err == nil {
			if template.RequestsHTTP != nil {
				fmt.Println("#", len(template.RequestsHTTP))
				fmt.Println(template.Info.Name)
				for i, requestHTTP := range template.RequestsHTTP {
					fmt.Println("####", i)
					fmt.Println("[+]", requestHTTP.Path)
					fmt.Println("[+]MatchersCondition", requestHTTP.MatchersCondition)
					for _, matcher := range requestHTTP.Matchers {
						fmt.Println("[+++++]")
						fmt.Println("[+][+]Condition", matcher.Condition, matcher.Type)
						fmt.Println("[+][+]Words", matcher.Words)
						fmt.Println("[+][+]Regex", matcher.Regex)
						fmt.Println("[+][+]DSL", matcher.DSL)
					}
				}
				fmt.Print("\n\n")
			} else {
				fmt.Println("[*]", template.Info.Name)
			}

		}
	}

}
