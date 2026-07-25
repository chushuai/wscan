package fetchup

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type Response struct {
	Req            *http.Request
	ResHeader      http.Header
	ProgressedBody io.Reader
	Close          func()
}

func (fu *Fetchup) Request(u string) (*Response, error) {
	req, err := http.NewRequestWithContext(fu.Ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}

	res, err := fu.HttpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return &Response{
		Req:            req,
		ResHeader:      res.Header,
		ProgressedBody: newProgress(fu.Ctx, res.Body, int(res.ContentLength), fu.MinReportSpan, fu.Logger),
		Close:          func() { _ = res.Body.Close() },
	}, nil
}

func (fu *Fetchup) Download(u string) error {
	fu.Logger.Println(EventDownload, u)

	res, err := fu.Request(u)
	if err != nil {
		return err
	}
	defer res.Close()

	r := res.ProgressedBody

	if strings.HasSuffix(u, ".gz") || res.ResHeader.Get("Content-Encoding") == "gzip" {
		u = strings.TrimSuffix(u, ".gz")
		r, err = gzip.NewReader(r)
		if err != nil {
			return err
		}
	}

	if strings.HasSuffix(u, ".tar") {
		err := fu.UnTar(r)
		if err != nil {
			return err
		}
	} else if strings.HasSuffix(u, ".zip") {
		err := fu.UnZip(r)
		if err != nil {
			return err
		}
	} else {
		err = os.MkdirAll(filepath.Dir(fu.To), 0755)
		if err != nil {
			return err
		}

		f, err := os.Create(fu.To)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = io.Copy(f, r)
		if err != nil {
			return err
		}
	}

	fu.Logger.Println(EventDownloaded, fu.To)

	return nil
}

func (fu *Fetchup) UnZip(r io.Reader) error {
	// Because zip format does not streaming, we need to read the whole file into memory.
	buf := bytes.NewBuffer(nil)

	_, err := io.Copy(buf, r)
	if err != nil {
		return err
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		return err
	}

	size := 0
	for _, f := range zr.File {
		size += int(f.UncompressedSize64)
	}

	fu.Logger.Println(EventUnzip, fu.To)

	progress := newProgress(fu.Ctx, r, size, fu.MinReportSpan, fu.Logger)

	for _, f := range zr.File {
		p := filepath.Join(fu.To, normalizePath(f.Name))

		if f.FileInfo().IsDir() {
			err := os.MkdirAll(p, f.Mode())
			if err != nil {
				return err
			}
			continue
		}

		r, err := f.Open()
		if err != nil {
			return err
		}

		if f.FileInfo().Mode()&os.ModeSymlink == os.ModeSymlink {
			buf := bytes.NewBuffer(nil)
			_, err = io.Copy(io.MultiWriter(buf, progress), r)
			if err != nil {
				return err
			}

			err = os.Symlink(normalizePath(buf.String()), p)
			if err != nil {
				return err
			}

			continue
		}

		err = os.MkdirAll(filepath.Dir(p), 0755)
		if err != nil {
			return err
		}

		dst, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		_, err = io.Copy(io.MultiWriter(dst, progress), r)
		if err != nil {
			return err
		}

		err = dst.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (fu *Fetchup) UnTar(r io.Reader) error {
	tr := tar.NewReader(r)

	for {
		if fu.Ctx.Err() != nil {
			return fu.Ctx.Err()
		}

		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return err
		}

		info := hdr.FileInfo()
		p := filepath.Join(fu.To, hdr.Name)

		if info.IsDir() {
			err = os.MkdirAll(p, info.Mode())
			if err != nil {
				return err
			}

			continue
		}

		err = os.MkdirAll(filepath.Dir(p), 0755)
		if err != nil {
			return err
		}

		if hdr.Linkname != "" {
			err = os.Symlink(hdr.Linkname, p)
			if err != nil {
				return err
			}

			continue
		}

		dst, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_TRUNC, info.Mode())
		if err != nil {
			return err
		}

		_, err = io.Copy(dst, tr)
		if err != nil {
			return err
		}

		err = dst.Close()
		if err != nil {
			return err
		}
	}

	return nil
}
