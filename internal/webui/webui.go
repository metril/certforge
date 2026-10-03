// Package webui serves the embedded single-page web UI, falling back to
// index.html for client-side routes. Build with -tags embedweb to embed
// internal/webui/dist; otherwise a placeholder page is served.
package webui

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
)

// Handler serves the embedded UI.
func Handler() http.Handler { return newHandler(assets()) }

// Client routes never end in a dotted segment (org slugs, UUID ids and tab
// names have no dots), so a missing path that does is a missing static file.

func newHandler(fsys fs.FS) http.Handler {
	files := http.FileServer(http.FS(fsys))
	return middleware.Compress(5)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" || strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name != "" && name != "index.html" {
			if st, err := fs.Stat(fsys, name); err == nil && !st.IsDir() {
				if strings.HasPrefix(name, "assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				files.ServeHTTP(w, r)
				return
			}
		}
		if name != "index.html" && (strings.HasPrefix(name, "assets/") || path.Ext(name) != "") {
			http.NotFound(w, r)
			return
		}
		serveIndex(w, fsys)
	}))
}

func serveIndex(w http.ResponseWriter, fsys fs.FS) {
	b, err := fs.ReadFile(fsys, "index.html")
	if err != nil {
		http.Error(w, "web UI not available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(b)
}
