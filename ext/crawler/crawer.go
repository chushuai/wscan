/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package crawler

import (
	"bytes"
	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"log"
	"net/http/cookiejar"
	"net/url"
	"os"
	"sync"
	"time"
	"wscan/core/utils/checker"
	"wscan/core/utils/collections"
)

type Body struct {
	buffer       *bytes.Buffer
	bufferBackup *bytes.Buffer
}

type Client struct {
	ctx                   context.Context
	Jar                   *cookiejar.Jar
	Client                *http.Client
	ClientWithoutRedirect *http.Client
	config                *ClientConfig
	limiter               *rate.Limiter
	requestTimeout        int64
	ClientStatistic
	respCountInTenSecond int32
	lastTenSecondTime    time.Time
	statisticMutex       sync.Mutex
}

type Crawler struct {
	CrawlerStatistic
	Client                  *Client
	filter                  Filter
	config                  *Config
	logger                  *log.Logger
	ctx                     context.Context
	cancel                  func()
	wg                      sync.WaitGroup
	taskChan                chan *task
	taskQueue               *collections.Queue
	feedEnded               bool
	entranceURLs            sync.Map
	allURLs                 sync.Map
	visitedURLs             sync.Map
	requestHandlers         []func(*http.Request) bool
	notVisitRequestHandlers []func(*http.Request, error)
	responseHandlers        []func(*http.Response) bool
	documentHandlers        []func(*url.URL, *goquery.Document, *http.Response, int) bool
	errorHandlers           []func(error)
	newURLsHandlers         []func(string)
	requestHandlersMutex    sync.Mutex
	responseHandlersMutex   sync.Mutex
	documentHandlersMutex   sync.Mutex
	errorHandlersMutex      sync.Mutex
	newTaskMutex            sync.Mutex
	newURLsHandlersMutex    sync.Mutex
	workingTasks            []*task
	chromeCtx               context.Context
	targetIDs               sync.Map
	tabLock                 sync.Mutex
	pkcs12File              *os.File
	tempFileForUpload       *os.File
	urlChecker              *checker.URLChecker
}

type task struct {
	req           *http.Request
	ireq          *http.Request
	redirectCount int
	depth         int
}
