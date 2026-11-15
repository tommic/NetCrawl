package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netcrawler/internal/store/memstore"
)

func TestUI(t *testing.T) {
	for _, embed := range []bool{false, true} {
		srv := httptest.NewServer(New(memstore.New(), Options{Embeddable: embed, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}).Handler())
		defer srv.Close()

		resp, err := http.Get(srv.URL + "/")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || !strings.Contains(string(body), "<title>NetCrawl</title>") || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
			t.Fatalf("embed=%v: GET / = %d %q", embed, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("CSP = %q", csp)
		}
		framed := strings.Contains(csp, "frame-ancestors 'none'") || resp.Header.Get("X-Frame-Options") == "DENY"
		if framed == embed {
			t.Errorf("embed=%v: frame protection = %v (CSP %q)", embed, framed, csp)
		}
		for _, asset := range []string{"/ui/app.js", "/ui/style.css"} {
			resp, err := http.Get(srv.URL + asset)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Errorf("%s = %d", asset, resp.StatusCode)
			}
		}
		if resp, _ := http.Get(srv.URL + "/nope"); resp.StatusCode != 404 {
			t.Errorf("unknown path = %d, want 404", resp.StatusCode)
		}
	}
}
