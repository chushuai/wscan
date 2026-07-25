/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package htmlcompare

import (
	"golang.org/x/net/html"
	"os"
	"regexp"
	"strings"
	"wscan/core/utils/comparer/strcompare"
)

type htmlFeature struct {
	Title       string
	ContentType string
	HeadToken   []string
	HtmlToken   []string
	TextToken   []string
}

type HTMLProcessor struct {
	data      []byte
	tokenizer *html.Tokenizer
	feature   *htmlFeature
}

func NewHTMLProcessorFromString(htmlString string) *HTMLProcessor {
	hp := &HTMLProcessor{
		data:      []byte(htmlString),
		tokenizer: html.NewTokenizer(strings.NewReader(htmlString)),
		feature:   &htmlFeature{},
	}
	hp.makeFeature()
	return hp
}

func (hp *HTMLProcessor) CompareHeadWith(refToken string) bool {
	for _, token := range hp.feature.HeadToken {
		if token == refToken {
			return true
		}
	}
	return false
}

func (hp *HTMLProcessor) CompareHtmlWith(refToken string) bool {
	for _, token := range hp.feature.HtmlToken {
		if token == refToken {
			return true
		}
	}
	return false
}

func (hp *HTMLProcessor) CompareTextWith(refToken string) bool {
	for _, token := range hp.feature.TextToken {
		if token == refToken {
			return true
		}
	}
	return false
}

func (hp *HTMLProcessor) CompareWith(refToken string) bool {
	return hp.CompareHeadWith(refToken) || hp.CompareHtmlWith(refToken) || hp.CompareTextWith(refToken)
}

func (hp *HTMLProcessor) DumpDataToFile(filePath string) error {
	return os.WriteFile(filePath, hp.data, 0644)
}

func (hp *HTMLProcessor) GetStringData() string {
	return string(hp.data)
}

func (hp *HTMLProcessor) MatchRegex(r *regexp.Regexp) bool {
	return r.Match(hp.data)
}

func (hp *HTMLProcessor) ReplaceRegex(r *regexp.Regexp, repl string) {
	hp.data = r.ReplaceAll(hp.data, []byte(repl))
}

func (hp *HTMLProcessor) makeFeature() {
	inHead := false
	for {
		tt := hp.tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return
		case html.StartTagToken:
			t := hp.tokenizer.Token()
			if t.Data == "head" {
				inHead = true
			} else if !inHead {
				hp.feature.HtmlToken = append(hp.feature.HtmlToken, t.Data)
			}
		case html.EndTagToken:
			t := hp.tokenizer.Token()
			if t.Data == "head" {
				inHead = false
			}
		case html.TextToken:
			data := strings.TrimSpace(hp.tokenizer.Token().Data)
			if data != "" {
				if inHead {
					hp.feature.HeadToken = append(hp.feature.HeadToken, data)
				} else {
					hp.feature.TextToken = append(hp.feature.TextToken, data)
				}
			}
		}
	}
}

func CompareHTMLProcessors(hp1, hp2 *HTMLProcessor) float32 {
	//titleSimilarity := strcompare.NewStringArrayComparer([]string{hp1.feature.Title}, []string{hp2.feature.Title}).Ratio()
	headSimilarity := strcompare.NewStringArrayComparer(hp1.feature.HeadToken, hp2.feature.HeadToken).Ratio()
	htmlSimilarity := strcompare.NewStringArrayComparer(hp1.feature.HtmlToken, hp2.feature.HtmlToken).Ratio()
	textSimilarity := strcompare.NewStringArrayComparer(hp1.feature.TextToken, hp2.feature.TextToken).Ratio()

	// You can calculate a weighted average or other metric depending on your requirements
	averageSimilarity := (headSimilarity + htmlSimilarity + textSimilarity) / 3
	return averageSimilarity
}
