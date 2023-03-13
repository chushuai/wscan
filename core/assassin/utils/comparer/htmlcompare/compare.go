/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package htmlcompare

import (
	"golang.org/x/net/html"
	"io/ioutil"
	"regexp"
	"strings"
)

type htmlFeature struct {
	Title     string
	HeadToken []string
	HtmlToken []string
	TextToken []string
}

type HTMLProcessor struct {
	data      []byte
	tokenizer *html.Tokenizer
	feature   *htmlFeature
}

func NewHTMLProcessorFromString(htmlString string) *HTMLProcessor {
	return &HTMLProcessor{
		data:      []byte(htmlString),
		tokenizer: html.NewTokenizer(strings.NewReader(htmlString)),
		feature:   &htmlFeature{},
	}
}

//*htmlcompare.HTMLProcessor
// func (*HTMLProcessor) CompareHeadWith()
func (hp *HTMLProcessor) CompareHeadWith(refToken string) bool {
	for _, token := range hp.feature.HeadToken {
		if token == refToken {
			return true
		}
	}
	return false
}

// func (*HTMLProcessor) CompareHtmlWith()
func (hp *HTMLProcessor) CompareHtmlWith(refToken string) bool {
	for _, token := range hp.feature.HtmlToken {
		if token == refToken {
			return true
		}
	}
	return false
}

// func (*HTMLProcessor) CompareTextWith()
func (hp *HTMLProcessor) CompareTextWith(refToken string) bool {
	for _, token := range hp.feature.TextToken {
		if token == refToken {
			return true
		}
	}
	return false
}

// func (*HTMLProcessor) CompareWith()
func (hp *HTMLProcessor) CompareWith(refToken string) bool {
	return hp.CompareHeadWith(refToken) || hp.CompareHtmlWith(refToken) || hp.CompareTextWith(refToken)
}

func (hp *HTMLProcessor) DumpDataToFile(filePath string) error {
	return ioutil.WriteFile(filePath, hp.data, 0644)
}

func (hp *HTMLProcessor) GetStringData() string {
	return string(hp.data)
}

func (hp *HTMLProcessor) MatchRegex(r *regexp.Regexp) bool {
	return r.Match(hp.data)
}

// func (*HTMLProcessor) ReplaceRegex()
func (hp *HTMLProcessor) ReplaceRegex(r *regexp.Regexp, repl string) {
	hp.data = r.ReplaceAll(hp.data, []byte(repl))
}

func (hp *HTMLProcessor) makeFeature() {
	for {
		tt := hp.tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return
		case html.StartTagToken:
			t := hp.tokenizer.Token()
			if t.Data == "title" {
				hp.tokenizer.Next()
				hp.feature.Title = hp.tokenizer.Token().Data
			} else if t.Data == "head" {
				hp.feature.HeadToken = append(hp.feature.HeadToken, t.Data)
			} else if t.Data == "html" {
				hp.feature.HtmlToken = append(hp.feature.HtmlToken, t.Data)
			}
		case html.TextToken:
			hp.feature.TextToken = append(hp.feature.TextToken, hp.tokenizer.Token().Data)
		}
	}
}
