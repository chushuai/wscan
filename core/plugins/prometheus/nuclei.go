/**
2 * @Author: shaochuyu
3 * @Date: 1/21/24
4 */

package prometheus

import (
	"context"
	"time"
	"wscan/core/plugins/prometheus/goby"
	logger "wscan/core/utils/log"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/input"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/ratelimit"
)

type Template = templates.Template

var (
	Results         []*goby.Result
	ExecuterOptions protocols.ExecutorOptions
)

func InitExecutorOptions(rate int, timeout int) (err error) {

	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	options := types.DefaultOptions()
	options.Timeout = timeout
	mockProgress := &MockProgressClient{}
	reportingClient, _ := reporting.New(&reporting.Options{}, "", true)
	defer reportingClient.Close()

	outputWriter := NewMockOutputWriter(options.OmitTemplate)
	outputWriter.WriteCallback = func(event *output.ResultEvent) {
		if event.MatcherStatus {
			logger.Infof("Found Nuclei Vuln: %v", event.TemplateID)

		}
	}

	_ = protocolstate.Init(options)
	_ = protocolinit.Init(options)

	interactOpts := interactsh.DefaultOptions(outputWriter, reportingClient, mockProgress)
	interactClient, err := interactsh.New(interactOpts)
	if err != nil {
		return
	}

	catalog := disk.NewCatalog("")

	ExecuterOptions = protocols.ExecutorOptions{
		Output:       outputWriter,
		Options:      options,
		Progress:     mockProgress,
		Catalog:      catalog,
		IssuesClient: reportingClient,
		Interactsh:   interactClient,
		RateLimiter:  ratelimit.New(context.Background(), 150, time.Second),
		Parser:       templates.NewParser(),
		InputHelper:  input.NewHelper(),
		//HostErrorsCache: cache,
		Colorizer: aurora.NewAurora(true),
		ResumeCfg: types.NewResumeCfg(),
	}
	ExecuterOptions.Options.RateLimit = rate

	return
}
