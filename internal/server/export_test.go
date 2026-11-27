package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"netcrawler/internal/store"
)

func TestExport(t *testing.T) {
	f := newNetFixture(t)
	ctx := context.Background()
	c := withCookie(f.login())
	if resp := f.do("POST", "/api/v1/admin/networks", "application/json",
		`{"crawler_id":"lan-1","name":"Heimnetz","targets":["10.0.0.0/24"],"deny":["10.0.0.99"]}`, c); resp.StatusCode != http.StatusCreated {
		t.Fatalf("network: %d", resp.StatusCode)
	}
	scanned := f.now
	err := f.st.UpdateInventory(ctx, 1, func(n *store.Network, hosts map[string]*store.Host) ([]string, []store.Event, error) {
		hosts["10.0.0.5"] = &store.Host{Hostname: "nas.fritz.box", Important: true, FirstSeen: f.now, LastSeen: f.now,
			PortsScannedAt: &scanned, Ports: []store.HostPort{
				{Port: 22, FirstSeen: f.now, LastSeen: f.now, Service: store.Service{Name: "ssh", Product: "OpenSSH", Version: "9.6p1", Extra: "Ubuntu Linux", Method: "nmap"}},
				{Port: 8080, FirstSeen: f.now, LastSeen: f.now, Service: store.Service{Name: "http", Method: "banner"}},
				{Port: 9999, FirstSeen: f.now, LastSeen: f.now},
			}}
		hosts["10.0.0.20"] = &store.Host{FirstSeen: f.now, LastSeen: f.now.Add(-48 * time.Hour), OfflineLevel: store.SeverityInfo}
		n.DiscoveryDoneAt = &scanned
		return []string{"10.0.0.5", "10.0.0.20"}, []store.Event{
			{At: f.now.Add(-time.Hour), IP: "10.0.0.5", Type: "port.opened", Severity: store.SeverityWarning, Message: "Port 8080 neu offen auf 10.0.0.5"},
			{At: f.now.Add(-30 * 24 * time.Hour), IP: "10.0.0.5", Type: "host.new", Severity: store.SeverityInfo, Message: "alt"},
		}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetHostCustomName(ctx, 1, "10.0.0.5", "NAS Keller"); err != nil {
		t.Fatal(err)
	}

	get := func(path string, auth string) (int, string) {
		t.Helper()
		resp := f.do("GET", path, "", "", func(r *http.Request) {
			if auth != "" {
				r.Header.Set("Authorization", "Bearer "+auth)
			}
		})
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	if code, _ := get("/api/v1/export.txt", ""); code != http.StatusUnauthorized {
		t.Fatalf("without token: %d", code)
	}
	if code, _ := get("/api/v1/export.txt", "nce_"+strings.Repeat("A", 43)); code != http.StatusUnauthorized {
		t.Fatalf("unknown token: %d", code)
	}

	// Create a token (shown once), use it via header and query.
	resp := f.do("POST", "/api/v1/admin/export-tokens", "application/json", `{"name":"KI-Agent"}`, c)
	tok := decode[ExportTokenView](t, resp)
	if resp.StatusCode != http.StatusCreated || !strings.HasPrefix(tok.Token, ExportTokenPrefix) || len(tok.Token) != 47 {
		t.Fatalf("create: %d %+v", resp.StatusCode, tok)
	}
	code, text := get("/api/v1/export.txt", tok.Token)
	if code != http.StatusOK {
		t.Fatalf("export: %d %s", code, text)
	}
	for _, want := range []string{
		"# NetCrawl-Inventar",
		"- Heimnetz: 10.0.0.0/24 (ohne 10.0.0.99) · Crawler lan-1 · 2 Geräte, 1 online",
		"- 10.0.0.5 NAS Keller (DNS: nas.fritz.box) · online · wichtig",
		"  22/tcp ssh, OpenSSH 9.6p1 (Ubuntu Linux)",
		"  8080/tcp http\n",
		"  9999/tcp Dienst unbekannt",
		"- 10.0.0.20 · offline seit",
		"  Ports: noch kein Portscan",
		"### Web\n- unbekannte Software [http]: 10.0.0.5:8080",
		"### Fernzugriff\n- OpenSSH 9.6p1 [ssh]: 10.0.0.5:22",
		"Warnung: Port 8080 neu offen auf 10.0.0.5",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("export lacks %q\n%s", want, text)
		}
	}
	if strings.Contains(text, ": alt") {
		t.Error("event older than 7 days listed")
	}
	if strings.Index(text, "10.0.0.5 ") > strings.Index(text, "10.0.0.20 ") {
		t.Error("devices not in numeric IP order")
	}
	if code, _ := get("/api/v1/export.txt?token="+tok.Token+"&days=0", ""); code != http.StatusOK {
		t.Errorf("token in query: %d", code)
	}
	if code, _ := get("/api/v1/export.txt?days=999", tok.Token); code != http.StatusBadRequest {
		t.Errorf("days=999: %d", code)
	}

	// The admin session works too (download in the web UI).
	if resp := f.do("GET", "/api/v1/export.txt?download=1", "", "", c); resp.StatusCode != http.StatusOK ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), "netcrawl-inventar.txt") {
		t.Errorf("admin download: %d %q", resp.StatusCode, resp.Header.Get("Content-Disposition"))
	}

	// Listed without the token, with its last use; deleted tokens stop working.
	list := decode[[]ExportTokenView](t, f.do("GET", "/api/v1/admin/export-tokens", "", "", c))
	if len(list) != 1 || list[0].Token != "" || list[0].LastUsedAt == nil {
		t.Fatalf("list = %+v", list)
	}
	if resp := f.do("DELETE", "/api/v1/admin/export-tokens/1", "application/json", "", c); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	if code, _ := get("/api/v1/export.txt", tok.Token); code != http.StatusUnauthorized {
		t.Errorf("deleted token still works: %d", code)
	}
	// An export token is no admin login.
	resp = f.do("POST", "/api/v1/admin/export-tokens", "application/json", `{"name":"zweiter"}`, c)
	tok2 := decode[ExportTokenView](t, resp)
	if code, _ := get("/api/v1/admin/networks", tok2.Token); code != http.StatusUnauthorized {
		t.Errorf("export token opened the admin API: %d", code)
	}
}
