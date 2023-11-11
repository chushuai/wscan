/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package crawler

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/net/idna"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
)

// AbsoluteURL returns an absolute URL based on the provided base URL and relative path.
func AbsoluteURL(base *url.URL, path string) *url.URL {
	absoluteURL := &url.URL{}
	*absoluteURL = *base
	absoluteURL.Path = path
	return absoluteURL
}

func ParsePKCS12(p12Data []byte, password string) (tls.Certificate, error) {
	certs, err := tls.X509KeyPair(p12Data, p12Data)
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(certs.Certificate) == 0 {
		return tls.Certificate{}, errors.New("no certificates found in PKCS#12 data")
	}
	return certs, nil
}

func requestHash(r *http.Request) (hash string, err error) {
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("error reading request body: %v", err)
	}

	r.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes)) // restore the original request body

	h := sha256.New()
	_, err = h.Write(bodyBytes)
	if err != nil {
		return "", fmt.Errorf("error hashing request body: %v", err)
	}

	hashBytes := h.Sum(nil)
	return hex.EncodeToString(hashBytes), nil
}

// redirectBehavior returns the behavior for following a redirect from the given
// request while maintaining the given network context.
func redirectBehavior(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	// Use the default behavior for the first redirect.
	if len(via) == 0 {
		return nil
	}
	// Only follow redirects if the method is GET or HEAD.
	prevReq := via[len(via)-1]
	if prevReq.Method != http.MethodGet && prevReq.Method != http.MethodHead {
		return errors.New("redirects not allowed with non-GET or HEAD requests")
	}
	// Only follow redirects to the same host.
	if prevReq.URL.Host != req.URL.Host {
		return errors.New("redirect to different host not allowed")
	}
	// Add the Referer header to the request.
	if _, ok := req.Header["Referer"]; !ok {
		req.Header.Set("Referer", prevReq.URL.String())
	}
	return nil
}

// refererForURL returns the Referer header value for the given URL.
func refererForURL(req *http.Request, targetURL *url.URL) string {
	refererPolicy := req.Referer()
	if refererPolicy == "" || refererPolicy == "unsafe-url" {
		// Always send the Referer header with the full URL
		return targetURL.String()
	} else if refererPolicy == "no-referrer" {
		// Don't send the Referer header
		return ""
	} else if refererPolicy == "origin" || refererPolicy == "origin-when-cross-origin" {
		// Send the Referer header with the origin of the request URL
		return req.URL.Scheme + "://" + req.URL.Host
	} else if refererPolicy == "same-origin" || refererPolicy == "strict-origin" || refererPolicy == "strict-origin-when-cross-origin" {
		// Send the Referer header with the full URL if it's from the same origin as the request URL, or with the origin otherwise
		if targetURL.Scheme == req.URL.Scheme && targetURL.Host == req.URL.Host {
			return targetURL.String()
		} else {
			return req.URL.Scheme + "://" + req.URL.Host
		}
	} else {
		// Invalid or unrecognized Referer policy, so send the full URL
		return targetURL.String()
	}
}

// shouldCopyHeaderOnRedirect determines whether the given header should be copied on a redirect.
func shouldCopyHeaderOnRedirect(header string, value []string) bool {
	// The following headers should not be copied on redirects:
	switch header {
	case "Authorization", "Cookie":
		return false
	}
	// By default, all other headers are copied:
	return true
}

// canonicalAddr returns the canonical form of the network address addr.
func canonicalAddr(addr string) string {
	return (&net.TCPAddr{IP: net.ParseIP(addr)}).String()
}

// idnaASCII returns the ASCII form of the given domain name using IDNA (RFC 5891).
func idnaASCII(s string) (string, error) {
	return idna.ToASCII(s)
}

// getParentPaths returns a slice of all parent paths of the given path.
func getParentPaths(path string) []string {
	var result []string
	dir := path
	for {
		dir = filepath.Dir(dir)
		if dir == "/" || dir == "." {
			break
		}
		result = append(result, dir)
	}
	return result
}
