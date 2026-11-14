package server

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed ui/*
var uiFiles embed.FS

// contentSecurityPolicy allows only the server's own scripts and styles;
// no inline code, no external resources.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'"

// registerUI serves the small admin UI at / and its assets under /ui/.
func (s *Server) registerUI(mux *http.ServeMux) {
	sub, _ := fs.Sub(uiFiles, "ui")
	assets := http.StripPrefix("/ui/", http.FileServer(http.FS(sub)))
	mux.Handle("GET /ui/", assets)
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		page, err := uiFiles.ReadFile("ui/index.html")
		if err != nil {
			s.internalError(w, err)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(page)
	})
}
