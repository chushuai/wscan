package fetchup

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type Fetchup struct {
	Ctx context.Context

	// To is the path to save the file.
	To string

	// URLs is the list of candidates, the fastest one will be used to download the file.
	URLs []string

	Logger Logger

	// SpeedPacketSize is the size of the packet used to calculate the download speed.
	// The size should be much smaller than the whole file size to download.
	SpeedPacketSize int

	MinReportSpan time.Duration

	HttpClient *http.Client
}

func New(to string, us ...string) *Fetchup {
	return &Fetchup{
		Ctx:             context.Background(),
		To:              to,
		URLs:            us,
		Logger:          log.New(os.Stderr, "", log.LstdFlags),
		SpeedPacketSize: 64 * 1024,
		MinReportSpan:   time.Second,
		HttpClient: &http.Client{
			Transport: &DefaultTransport{UA: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36"},
		},
	}
}

func (fu *Fetchup) Fetch() error {
	u := fu.FastestURL()
	if u == "" {
		return &ErrNoURLs{fu.URLs}
	}

	return fu.Download(u)
}

type ErrNoURLs struct {
	URLs []string
}

func (e *ErrNoURLs) Error() string {
	return fmt.Sprintf("Not able to find a valid URL to download %v", e.URLs)
}

func (fu *Fetchup) FastestURL() (fastest string) {
	setURL := sync.Once{}
	ctx, cancel := context.WithCancel(fu.Ctx)
	defer cancel()

	wg := sync.WaitGroup{}
	for _, u := range fu.URLs {
		u := u

		wg.Add(1)

		go func() {
			defer wg.Done()

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				return
			}

			res, err := fu.HttpClient.Do(req)
			if err != nil {
				return
			}
			defer func() { _ = res.Body.Close() }()

			if res.StatusCode == http.StatusOK {
				buf := make([]byte, fu.SpeedPacketSize)
				_, err = io.ReadFull(res.Body, buf)
				if err != nil {
					return
				}

				setURL.Do(func() {
					fastest = u
					cancel()
				})
			}
		}()
	}
	wg.Wait()

	return
}
