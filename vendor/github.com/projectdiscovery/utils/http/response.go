package httputil

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

var (
	// MaxBodyRead is the maximum size of HTTP response body to read.
	//
	// Responses larger than this will be truncated.
	//
	// Deprecated: Use [DefaultMaxBodySize] instead.
	MaxBodyRead = 4 * 1024 * 1024 // 4 MB
)

// DumpResponseIntoBuffer dumps a http response without allocating a new buffer
// for the response body.
func DumpResponseIntoBuffer(resp *http.Response, body bool, buff *bytes.Buffer) (err error) {
	if resp == nil {
		return fmt.Errorf("response is nil")
	}
	save := resp.Body
	savecl := resp.ContentLength

	if !body {
		// For content length of zero. Make sure the body is an empty
		// reader, instead of returning error through failureToReadBody{}.
		if resp.ContentLength == 0 {
			resp.Body = emptyBody
		} else {
			resp.Body = failureToReadBody{}
		}
	} else if resp.Body == nil {
		resp.Body = emptyBody
	} else {
		save, resp.Body, err = drainBody(resp.Body)
		if err != nil {
			return err
		}
	}
	err = resp.Write(buff)
	if err == errNoBody {
		err = nil
	}
	resp.Body = save
	resp.ContentLength = savecl
	return
}

// DrainResponseBody drains the response body and closes it.
//
// This reads and discards up to MaxBodyRead bytes to check for any remaining
// data, then closes the connection. This prevents connection reuse for responses
// that exceed the expected size (potential DoS).
func DrainResponseBody(resp *http.Response) {
	defer func() {
		_ = resp.Body.Close()
	}()
	// Drain up to MaxBodyRead to check for oversized responses
	_, _ = io.CopyN(io.Discard, resp.Body, int64(MaxBodyRead))
}
