package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netcrawler/internal/protocol"
	"netcrawler/internal/store/memstore"
)

func TestUpdateCrawlerRelease(t *testing.T) {
	f := newNetFixture(t) // crawler lan-1: 10.0.0.0/24, 256 hosts
	ctx := context.Background()
	cookie := withCookie(f.login())
	put := func(body string) (int, string) {
		resp := f.do("PUT", "/api/v1/admin/crawlers/lan-1", "application/json", body, cookie)
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if _, err := CreateNetwork(ctx, f.st, "test", NetworkRequest{CrawlerID: "lan-1", Name: "LAN", Targets: []string{"10.0.0.0/25"}}, f.now); err != nil {
		t.Fatal(err)
	}
	if err := f.server.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.jobs()) == 0 {
		t.Fatal("no scheduled job")
	}

	cases := []struct {
		body, want string
	}{
		{`{"allow":["10.0.0.0/24"]}`, "both allow and max_hosts"},
		{`{"allow":["10.0.0.0/24"],"max_hosts":256}`, "unchanged"},
		{`{"allow":["8.8.8.0/24"],"max_hosts":256}`, "private"},
		{`{"allow":["10.0.1.0/24"],"max_hosts":256}`, `network \"LAN\" does not fit`},
		{`{"allow":["10.0.0.0/24"],"max_hosts":64}`, `network \"LAN\" does not fit`},
	}
	for _, c := range cases {
		if status, body := put(c.body); status != 400 || !strings.Contains(body, c.want) {
			t.Errorf("%s: %d %s", c.body, status, body)
		}
	}
	if got, _ := f.st.Crawler(ctx, "lan-1"); got.ReinstallRequired || got.MaxHosts != 256 {
		t.Fatalf("rejected change was applied: %+v", got)
	}

	status, body := put(`{"allow":["10.0.0.0/24","192.168.40.0/24"],"max_hosts":512}`)
	if status != 200 || !strings.Contains(body, `"reinstall_required":true`) {
		t.Fatalf("update: %d %s", status, body)
	}
	got, _ := f.st.Crawler(ctx, "lan-1")
	if strings.Join(got.Allow, ",") != "10.0.0.0/24,192.168.40.0/24" || got.MaxHosts != 512 {
		t.Fatalf("crawler %+v", got)
	}
	// Jobs planned under the old release are not delivered any more.
	if resp := f.signedPollFor("lan-1"); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("poll after release change: %d", resp.StatusCode)
	}
	audit, _ := f.st.ListAudit(ctx, 10)
	if audit[0].Action != "crawler.release" || !strings.Contains(string(audit[0].Details), "old_allow") {
		t.Fatalf("audit %s %s", audit[0].Action, audit[0].Details)
	}
}

func TestPublicURLSetting(t *testing.T) {
	f := &fixture{t: t, st: memstore.New(), now: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	pin := "sha256//" + strings.Repeat("A", 43) + "="
	s := New(f.st, Options{Now: func() time.Time { return f.now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		InstallDefaults: InstallConfig{TLSPin: pin, AgentDir: t.TempDir()}})
	f.srv = httptest.NewServer(s.Handler())
	t.Cleanup(f.srv.Close)
	ctx := context.Background()
	hash, _ := HashPassword(testPassword)
	_ = f.st.SetAdmin(ctx, "admin", hash)
	if _, _, err := CreateCrawler(ctx, f.st, "test", CrawlerRequest{ID: "lan-1", Allow: []string{"10.0.0.0/24"}, MaxHosts: 256}, f.now); err != nil {
		t.Fatal(err)
	}
	cookie := withCookie(f.login())

	enroll := func() int {
		return f.do("POST", "/api/v1/admin/crawlers/lan-1/enroll", "application/json", `{}`, cookie).StatusCode
	}
	if enroll() != 400 {
		t.Fatal("installer active without public URL")
	}
	for _, bad := range []string{`{"public_url":"http://192.168.1.5:8080"}`, `{"public_url":"https://x/y"}`, `{"public_url":""}`} {
		if resp := f.do("PUT", "/api/v1/admin/settings/public-url", "application/json", bad, cookie); resp.StatusCode != 400 {
			t.Errorf("%s: %d", bad, resp.StatusCode)
		}
	}
	resp := f.do("PUT", "/api/v1/admin/settings/public-url", "application/json", `{"public_url":"https://192.168.1.5:8443/"}`, cookie)
	var v PublicURLView
	if err := decodeInto(resp, &v); err != nil || resp.StatusCode != 200 {
		t.Fatalf("set: %d %v", resp.StatusCode, err)
	}
	if v.PublicURL != "https://192.168.1.5:8443" || v.Source != "ui" || v.TLSPin != pin {
		t.Fatalf("view %+v", v)
	}
	r := f.do("POST", "/api/v1/admin/crawlers/lan-1/enroll", "application/json", `{}`, cookie)
	var ev EnrollmentView
	if err := decodeInto(r, &ev); err != nil || r.StatusCode != 201 {
		t.Fatalf("enroll after setting URL: %d", r.StatusCode)
	}
	if !strings.Contains(ev.Command, "--pinnedpubkey '"+pin+"'") || !strings.Contains(ev.Command, "https://192.168.1.5:8443/install/") {
		t.Fatalf("command %s", ev.Command)
	}
	// The script is served with the UI-configured URL.
	token := ev.Command[strings.Index(ev.Command, "/install/")+len("/install/"):]
	token = token[:strings.Index(token, "'")]
	if !protocol.ValidToken(token) {
		t.Fatalf("token %q", token)
	}
	sr := f.do("GET", "/install/"+token, "", "", nil)
	if b, _ := io.ReadAll(sr.Body); sr.StatusCode != 200 || !strings.Contains(string(b), "SERVER_URL='https://192.168.1.5:8443'") {
		t.Fatalf("script: %d", sr.StatusCode)
	}
	audit, _ := f.st.ListAudit(ctx, 5)
	found := false
	for _, a := range audit {
		found = found || a.Action == "settings.public_url"
	}
	if !found {
		t.Error("no audit entry")
	}
}

func decodeInto(resp *http.Response, v any) error {
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}
