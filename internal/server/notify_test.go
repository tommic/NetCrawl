package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"netcrawler/internal/store"
	"netcrawler/internal/store/memstore"
)

const testHook = "https://discord.com/api/webhooks/123456789012345678/SECRET-token_abc"

// fakeDiscord records webhook posts; all requests to discord.com are
// routed to it.
type fakeDiscord struct {
	mu     sync.Mutex
	status int
	posts  []string
	srv    *httptest.Server
}

func (d *fakeDiscord) RoundTrip(r *http.Request) (*http.Response, error) {
	target, _ := url.Parse(d.srv.URL)
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host = target.Scheme, target.Host
	return http.DefaultTransport.RoundTrip(r)
}

func (d *fakeDiscord) got() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.posts...)
}

func newNotifyFixture(t *testing.T) (*fixture, *Server, *fakeDiscord, int64) {
	t.Helper()
	d := &fakeDiscord{status: http.StatusNoContent}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		d.mu.Lock()
		if r.URL.Path == "/api/webhooks/123456789012345678/SECRET-token_abc" {
			d.posts = append(d.posts, string(b))
		}
		status := d.status
		d.mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(d.srv.Close)

	f := &fixture{t: t, st: memstore.New(), now: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	s := New(f.st, Options{Now: func() time.Time { return f.now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		NotifyHTTP: &http.Client{Transport: d}})
	f.srv = httptest.NewServer(s.Handler())
	t.Cleanup(f.srv.Close)
	ctx := context.Background()
	hash, _ := HashPassword(testPassword)
	_ = f.st.SetAdmin(ctx, "admin", hash)
	if _, _, err := CreateCrawler(ctx, f.st, "test", CrawlerRequest{ID: "lan-1", Allow: []string{"10.0.0.0/24"}, MaxHosts: 256}, f.now); err != nil {
		t.Fatal(err)
	}
	n, err := CreateNetwork(ctx, f.st, "test", NetworkRequest{CrawlerID: "lan-1", Name: "Heimnetz", Targets: []string{"10.0.0.0/24"}}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return f, s, d, n.ID
}

func addEvents(t *testing.T, st store.Store, netID int64, events ...store.Event) {
	t.Helper()
	if err := st.UpdateInventory(context.Background(), netID, func(*store.Network, map[string]*store.Host) ([]string, []store.Event, error) {
		return nil, events, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestNotifications(t *testing.T) {
	f, s, d, netID := newNotifyFixture(t)
	ctx := context.Background()
	cookie := withCookie(f.login())
	put := func(body string) *http.Response {
		return f.do("PUT", "/api/v1/admin/notifications", "application/json", body, cookie)
	}

	// An event before notifications are enabled is never sent.
	addEvents(t, f.st, netID, store.Event{At: f.now.Add(-time.Hour), IP: "10.0.0.9", Type: "port.opened", Severity: "warning", Message: "alt"})

	if resp := put(`{"enabled":true}`); resp.StatusCode != 400 {
		t.Fatalf("enable without URL: %d", resp.StatusCode)
	}
	if resp := put(`{"discord_url":"https://evil.org/api/webhooks/1/x","enabled":true}`); resp.StatusCode != 400 {
		t.Fatalf("foreign URL: %d", resp.StatusCode)
	}
	resp := put(`{"discord_url":"` + testHook + `","min_severity":"warning","enabled":true}`)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || strings.Contains(string(body), "SECRET") || !strings.Contains(string(body), "/123456789012345678/") {
		t.Fatalf("save: %d %s", resp.StatusCode, body)
	}
	get := f.do("GET", "/api/v1/admin/notifications", "", "", cookie)
	if b, _ := io.ReadAll(get.Body); strings.Contains(string(b), "SECRET") {
		t.Fatalf("GET leaks the token: %s", b)
	}

	// Test message.
	if resp := f.do("POST", "/api/v1/admin/notifications/test", "application/json", `{}`, cookie); resp.StatusCode != 200 {
		t.Fatalf("test: %d", resp.StatusCode)
	}
	if p := d.got(); len(p) != 1 || !strings.Contains(p[0], "Testnachricht") {
		t.Fatalf("test post: %v", p)
	}

	// New events: warning and critical are sent in one message, info not.
	f.now = f.now.Add(time.Minute)
	addEvents(t, f.st, netID,
		store.Event{At: f.now, IP: "10.0.0.5", Type: "port.opened", Severity: "warning", Message: "Port 22 neu offen auf 10.0.0.5"},
		store.Event{At: f.now, IP: "10.0.0.6", Type: "host.new", Severity: "info", Message: "Neuer Host 10.0.0.6"},
		store.Event{At: f.now, IP: "10.0.0.7", Type: "host.offline", Severity: "critical", Message: "Host seit 7 Tagen nicht gesehen"},
		store.Event{At: f.now, IP: "10.0.0.8", Type: "port.opened", Severity: "warning", Message: "baseline", Baseline: true},
	)
	if err := s.Notify(ctx); err != nil {
		t.Fatal(err)
	}
	posts := d.got()
	if len(posts) != 2 {
		t.Fatalf("posts: %d", len(posts))
	}
	msg := posts[1]
	for _, want := range []string{"NetCrawl: 2 Änderungen", "Port 22 neu offen", "7 Tagen", "Heimnetz", `"allowed_mentions":{"parse":[]}`} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q: %s", want, msg)
		}
	}
	for _, not := range []string{"Neuer Host", "alt", "baseline"} {
		if strings.Contains(msg, not) {
			t.Errorf("message contains %q", not)
		}
	}
	if err := s.Notify(ctx); err != nil || len(d.got()) != 2 {
		t.Fatalf("resent: %d posts", len(d.got()))
	}

	// Failure: status recorded, event kept, retry after the backoff.
	d.mu.Lock()
	d.status = http.StatusInternalServerError
	d.mu.Unlock()
	f.now = f.now.Add(time.Minute)
	addEvents(t, f.st, netID, store.Event{At: f.now, IP: "10.0.0.5", Type: "port.opened", Severity: "warning", Message: "Port 80 neu offen"})
	_ = s.Notify(ctx)
	set, _ := f.st.NotificationSettings(ctx)
	if set.LastError == "" || strings.Contains(set.LastError, "SECRET") {
		t.Fatalf("last error %q", set.LastError)
	}
	d.mu.Lock()
	d.status = http.StatusNoContent
	d.mu.Unlock()
	n := len(d.got())
	f.now = f.now.Add(30 * time.Second)
	_ = s.Notify(ctx)
	if len(d.got()) != n {
		t.Fatal("retried before the backoff")
	}
	f.now = f.now.Add(time.Minute)
	_ = s.Notify(ctx)
	if p := d.got(); len(p) != n+1 || !strings.Contains(p[len(p)-1], "Port 80") {
		t.Fatalf("retry: %v", p[n:])
	}
	if set, _ = f.st.NotificationSettings(ctx); set.LastError != "" || set.LastSentAt == nil {
		t.Fatalf("status after success: %+v", set)
	}

	// Audit entries never contain the token.
	audit, _ := f.st.ListAudit(ctx, 50)
	for _, a := range audit {
		if strings.Contains(string(a.Details), "SECRET") {
			t.Fatalf("audit leaks token: %s %s", a.Action, a.Details)
		}
	}

	// Disabled: nothing is sent.
	if resp := put(`{"min_severity":"warning","enabled":false}`); resp.StatusCode != 200 {
		t.Fatal("disable")
	}
	f.now = f.now.Add(time.Minute)
	addEvents(t, f.st, netID, store.Event{At: f.now, IP: "10.0.0.5", Type: "port.opened", Severity: "critical", Message: "x"})
	_ = s.Notify(ctx)
	if len(d.got()) != n+1 {
		t.Fatal("sent while disabled")
	}
	var v NotificationView
	g := f.do("GET", "/api/v1/admin/notifications", "", "", cookie)
	_ = json.NewDecoder(g.Body).Decode(&v)
	if !v.DiscordConfigured || v.Enabled {
		t.Fatalf("view %+v", v)
	}
}
