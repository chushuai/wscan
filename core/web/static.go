/**
* @Author: shaochuyu
* @Date: 7/25/2026
*
* Static asset serving for the WebUI. The SPA (index.html + app.js + style.css
* + icons.js) is embedded at build time so the binary is fully self-contained.
 */
package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed webui/*
var webuiFS embed.FS

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}
	// SPA fallback: any unknown non-API path serves index.html (the app is
	// hash-routed, so deep links still work).
	full := "webui/" + path
	data, err := webuiFS.ReadFile(full)
	if err != nil {
		if r.URL.Path != "/" {
			data, err = webuiFS.ReadFile("webui/index.html")
			if err != nil {
				http.NotFound(w, r)
				return
			}
			path = "index.html"
		} else {
			http.NotFound(w, r)
			return
		}
	}
	setContentType(w, path)
	_, _ = w.Write(data)
}

func setContentType(w http.ResponseWriter, name string) {
	switch {
	case strings.HasSuffix(name, ".html"):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case strings.HasSuffix(name, ".css"):
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case strings.HasSuffix(name, ".json"):
		w.Header().Set("Content-Type", "application/json")
	case strings.HasSuffix(name, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
}

// keep fs referenced for future directory-listing needs
var _ = fs.ValidPath
