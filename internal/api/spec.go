package api

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"

	"github.com/metril/certforge/internal/api/gen"
)

//go:embed docs
var docsFS embed.FS

var specJSON = sync.OnceValues(func() ([]byte, error) {
	sw, err := gen.GetSwagger()
	if err != nil {
		return nil, err
	}
	return json.Marshal(sw)
})

func serveSpec(w http.ResponseWriter, _ *http.Request) {
	b, err := specJSON()
	if err != nil {
		Write(w, http.StatusInternalServerError, "OpenAPI document unavailable", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func mountDocs(r chi.Router) {
	sub, err := fs.Sub(docsFS, "docs")
	if err != nil {
		panic(err)
	}
	r.Get("/api/docs", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/api/docs/", http.StatusMovedPermanently)
	})
	r.Handle("/api/docs/*", http.StripPrefix("/api/docs/", http.FileServer(http.FS(sub))))
}
