package fetchup

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Logger interface
type Logger interface {
	// Same as fmt.Printf
	Println(...interface{})
}

// Log type for Println
type Log func(msg ...interface{})

// Println interface
func (l Log) Println(msg ...interface{}) {
	l(msg...)
}

// LoggerQuiet does nothing
var LoggerQuiet Logger = Log(func(_ ...interface{}) {})

// MultiLogger is similar to https://golang.org/pkg/io/#MultiWriter
func MultiLogger(list ...Logger) Log {
	return Log(func(msg ...interface{}) {
		for _, lg := range list {
			lg.Println(msg...)
		}
	})
}

type progress struct {
	ctx     context.Context
	s       io.Reader
	total   int
	count   int
	logger  Logger
	last    time.Time
	minSpan time.Duration
}

var _ io.ReadWriter = &progress{}

// newProgress returns a new progress reader.
func newProgress(ctx context.Context, s io.Reader, total int, minSpan time.Duration, logger Logger) *progress {
	return &progress{
		ctx:     ctx,
		s:       s,
		total:   total,
		logger:  logger,
		minSpan: minSpan,
	}
}

func (p *progress) Read(b []byte) (n int, err error) {
	if p.ctx.Err() != nil {
		return 0, p.ctx.Err()
	}

	n, err = p.s.Read(b)

	p.count += n

	if err != nil {
		return
	}

	if time.Since(p.last) < p.minSpan {
		return
	}

	p.last = time.Now()
	p.report()

	return
}

func (p *progress) Write(b []byte) (n int, err error) {
	if p.ctx.Err() != nil {
		return len(b), p.ctx.Err()
	}

	n = len(b)

	p.count += n

	if time.Since(p.last) < p.minSpan {
		return
	}

	p.last = time.Now()
	p.report()

	return
}

func (p *progress) report() {
	out := ""
	if p.total > 0 {
		out = fmt.Sprintf("%02d%%", p.count*100/p.total)
	} else {
		out = fmt.Sprintf("%.3fMB", float64(p.count)/1024/1024)
	}
	p.logger.Println(EventProgress, out)
}

func CacheDir() string {
	return filepath.Join(map[string]string{
		"windows": filepath.Join(os.Getenv("APPDATA")),
		"darwin":  filepath.Join(os.Getenv("HOME"), ".cache"),
		"linux":   filepath.Join(os.Getenv("HOME"), ".cache"),
	}[runtime.GOOS])
}

// StripFirstDir removes the first dir but keep all its children.
func StripFirstDir(dir string) error {
	list, err := readDir(dir)
	if err != nil {
		return err
	}

	name := ""
	for _, f := range list {
		if f.IsDir() {
			if name != "" {
				return fmt.Errorf("expected only one dir in %s", dir)
			}

			name = f.Name()
			continue
		}
	}

	if name == "" {
		return fmt.Errorf("no dir found under %s", dir)
	}

	root := filepath.Join(dir, name)
	up := filepath.Join(filepath.Dir(dir))
	toName := filepath.Base(dir)

	b := make([]byte, 8)
	_, err = rand.Read(b)
	if err != nil {
		return err
	}
	tmp := filepath.Join(up, fmt.Sprintf("%x", b))

	err = os.Rename(root, tmp)
	if err != nil {
		return err
	}
	err = os.RemoveAll(dir)
	if err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(up, toName))
}

func readDir(dir string) ([]os.FileInfo, error) {
	dirFile, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dirFile.Close() }()

	list, err := dirFile.Readdir(0)
	if err != nil {
		return nil, err
	}

	return list, nil
}

func normalizePath(p string) string {
	p = strings.ReplaceAll(p, "\\", string(filepath.Separator))
	return strings.ReplaceAll(p, "/", string(filepath.Separator))
}

// DefaultTransport is the default http transport for fetchup, it auto handles the gzip and user-agent.
type DefaultTransport struct {
	UA string
}

var _ http.RoundTripper = (*DefaultTransport)(nil)

func (t *DefaultTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("User-Agent", t.UA)
	req.Header.Set("Accept-Encoding", "gzip")
	return http.DefaultTransport.RoundTrip(req)
}
