package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"netcrawler/internal/protocol"
	"netcrawler/internal/store"
	"netcrawler/internal/store/memstore"
)

const testPassword = "correct-horse-battery"

type fixture struct {
	t      *testing.T
	st     *memstore.Store
	now    time.Time
	srv    *httptest.Server
	secret []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{t: t, st: memstore.New(), now: time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)}
	s := New(f.st, Options{Now: func() time.Time { return f.now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	f.srv = httptest.NewServer(s.Handler())
	t.Cleanup(f.srv.Close)
	hash, err := HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetAdmin(context.Background(), "admin", hash); err != nil {
		t.Fatal(err)
	}
	_, secret, err := CreateCrawler(context.Background(), f.st, "test", CrawlerRequest{ID: "lab-1", Allow: []string{"127.0.0.1/32"}, MaxHosts: 1}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.secret, _ = protocol.DecodeKey(secret)
	return f
}

func (f *fixture) do(method, path, contentType, body string, mod func(*http.Request)) *http.Response {
	f.t.Helper()
	req, _ := http.NewRequest(method, f.srv.URL+path, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if mod != nil {
		mod(req)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func (f *fixture) login() *http.Cookie {
	f.t.Helper()
	resp := f.do("POST", "/api/v1/admin/login", "application/json", `{"username":"admin","password":"`+testPassword+`"}`, nil)
	if resp.StatusCode != http.StatusOK {
		f.t.Fatalf("login: %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookie {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				f.t.Errorf("cookie flags: %+v", c)
			}
			return c
		}
	}
	f.t.Fatal("no session cookie")
	return nil
}

func withCookie(c *http.Cookie) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(c) }
}

func TestHealthz(t *testing.T) {
	f := newFixture(t)
	resp := f.do("GET", "/healthz", "", "", nil)
	if resp.StatusCode != 200 || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("healthz: %d %v", resp.StatusCode, resp.Header)
	}
}

func TestAdminAuth(t *testing.T) {
	f := newFixture(t)
	if resp := f.do("GET", "/api/v1/admin/crawlers", "", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", resp.StatusCode)
	}
	if resp := f.do("GET", "/api/v1/admin/crawlers", "", "", func(r *http.Request) { r.Header.Set("Authorization", "Bearer nope") }); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad token: %d, want 401", resp.StatusCode)
	}
	if resp := f.do("POST", "/api/v1/admin/login", "application/json", `{"username":"admin","password":"wrong-password"}`, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", resp.StatusCode)
	}
	if resp := f.do("POST", "/api/v1/admin/login", "application/json", `{"username":"nobody","password":"`+testPassword+`"}`, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unknown user: %d", resp.StatusCode)
	}
	if resp := f.do("POST", "/api/v1/admin/login", "application/x-www-form-urlencoded", `username=admin`, nil); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("form login: %d, want 415", resp.StatusCode)
	}

	c := f.login()
	resp := f.do("GET", "/api/v1/admin/me", "", "", withCookie(c))
	var me map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&me)
	if resp.StatusCode != 200 || me["username"] != "admin" {
		t.Errorf("me: %d %v", resp.StatusCode, me)
	}
	// CSRF: cookie-authenticated writes need a JSON content type.
	if resp := f.do("POST", "/api/v1/admin/jobs", "text/plain", `{}`, withCookie(c)); resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Errorf("text/plain POST with cookie: %d, want 415", resp.StatusCode)
	}
	// Session expiry.
	f.now = f.now.Add(13 * time.Hour)
	if resp := f.do("GET", "/api/v1/admin/me", "", "", withCookie(c)); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expired session: %d, want 401", resp.StatusCode)
	}
	// Logout invalidates the session.
	f.now = f.now.Add(-13 * time.Hour)
	f.do("POST", "/api/v1/admin/logout", "", "", withCookie(c))
	if resp := f.do("GET", "/api/v1/admin/me", "", "", withCookie(c)); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("after logout: %d, want 401", resp.StatusCode)
	}
}

func TestLoginRateLimit(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < maxLoginFailures; i++ {
		f.do("POST", "/api/v1/admin/login", "application/json", `{"username":"admin","password":"wrong-password"}`, nil)
	}
	resp := f.do("POST", "/api/v1/admin/login", "application/json", `{"username":"admin","password":"`+testPassword+`"}`, nil)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("after %d failures: %d, want 429 with Retry-After", maxLoginFailures, resp.StatusCode)
	}
	f.now = f.now.Add(loginWindow + time.Second)
	f.login()
}

func TestAdminCrawlersAndJobs(t *testing.T) {
	f := newFixture(t)
	c := withCookie(f.login())

	resp := f.do("POST", "/api/v1/admin/crawlers", "application/json", `{"id":"lab-2","allow":["127.0.0.1/32"],"max_hosts":1}`, c)
	var created struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&created)
	if resp.StatusCode != http.StatusCreated || created.ID != "lab-2" {
		t.Fatalf("create crawler: %d %+v", resp.StatusCode, created)
	}
	if _, err := protocol.DecodeKey(created.Secret); err != nil {
		t.Errorf("secret: %v", err)
	}
	for name, body := range map[string]string{
		"duplicate":    `{"id":"lab-2","allow":["127.0.0.1/32"],"max_hosts":1}`,
		"public range": `{"id":"lab-3","allow":["8.8.8.0/24"],"max_hosts":256}`,
		"bad id":       `{"id":"Lab 3","allow":["127.0.0.1/32"],"max_hosts":1}`,
		"unknown key":  `{"id":"lab-3","allow":["127.0.0.1/32"],"max_hosts":1,"x":1}`,
		"max hosts 0":  `{"id":"lab-3","allow":["127.0.0.1/32"],"max_hosts":0}`,
		"no allowlist": `{"id":"lab-3","max_hosts":1}`,
	} {
		if resp := f.do("POST", "/api/v1/admin/crawlers", "application/json", body, c); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, resp.StatusCode)
		}
	}

	resp = f.do("GET", "/api/v1/admin/crawlers", "", "", c)
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "secret") {
		t.Errorf("crawler list leaks secrets: %s", body)
	}

	resp = f.do("POST", "/api/v1/admin/jobs", "application/json", `{"crawler_id":"lab-1","targets":["127.0.0.1/32"],"ports":[22,80]}`, c)
	var job JobView
	_ = json.NewDecoder(resp.Body).Decode(&job)
	if resp.StatusCode != http.StatusCreated || job.Status != store.JobPending || job.MaxHosts != 1 || job.TimeoutMs != DefaultJobTimeoutMs ||
		!job.ExpiresAt.Equal(f.now.Add(DefaultJobTTL)) || job.CreatedBy != "admin" {
		t.Fatalf("create job: %d %+v", resp.StatusCode, job)
	}
	for name, body := range map[string]string{
		"out of scope":    `{"crawler_id":"lab-1","targets":["127.0.0.2/32"],"ports":[22]}`,
		"unknown crawler": `{"crawler_id":"nope","targets":["127.0.0.1/32"],"ports":[22]}`,
		"no ports":        `{"crawler_id":"lab-1","targets":["127.0.0.1/32"],"ports":[]}`,
		"ttl too long":    `{"crawler_id":"lab-1","targets":["127.0.0.1/32"],"ports":[22],"ttl_seconds":7200}`,
		"ttl too short":   `{"crawler_id":"lab-1","targets":["127.0.0.1/32"],"ports":[22],"ttl_seconds":10}`,
		"timeout":         `{"crawler_id":"lab-1","targets":["127.0.0.1/32"],"ports":[22],"timeout_ms":60000}`,
	} {
		if resp := f.do("POST", "/api/v1/admin/jobs", "application/json", body, c); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, resp.StatusCode)
		}
	}

	resp = f.do("GET", "/api/v1/admin/jobs/"+job.ID, "", "", c)
	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || strings.Contains(string(body), "result_token") || strings.Contains(string(body), "ResultToken") {
		t.Errorf("get job: %d %s", resp.StatusCode, body)
	}
	if resp := f.do("GET", "/api/v1/admin/jobs/nope", "", "", c); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown job: %d", resp.StatusCode)
	}
	resp = f.do("GET", "/api/v1/admin/audit", "", "", c)
	body, _ = io.ReadAll(resp.Body)
	for _, action := range []string{"admin.login", "crawler.create", "job.create"} {
		if !strings.Contains(string(body), action) {
			t.Errorf("audit log misses %s: %s", action, body)
		}
	}
}

// signedPoll builds a job poll request; mods may break it.
func (f *fixture) signedPoll(mod func(h http.Header, ts *int64, key *[]byte)) *http.Response {
	f.t.Helper()
	nonce, _ := protocol.NewNonce()
	ts := f.now.Unix()
	key := f.secret
	h := http.Header{}
	h.Set(protocol.HeaderCrawlerID, "lab-1")
	h.Set(protocol.HeaderRequestNonce, nonce)
	if mod != nil {
		mod(h, &ts, &key)
	}
	h.Set(protocol.HeaderRequestTimestamp, strconv.FormatInt(ts, 10))
	if h.Get(protocol.HeaderRequestHMAC) == "" {
		h.Set(protocol.HeaderRequestHMAC, protocol.Sign(key, protocol.SigningString("GET", protocol.PathJob, h.Get(protocol.HeaderCrawlerID), "", ts, h.Get(protocol.HeaderRequestNonce), nil)))
	}
	return f.do("GET", protocol.PathJob, "", "", func(r *http.Request) {
		for k, v := range h {
			r.Header[k] = v
		}
	})
}

func TestJobPoll(t *testing.T) {
	f := newFixture(t)
	if resp := f.signedPoll(nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("no job: %d, want 204", resp.StatusCode)
	}
	j, err := CreateJob(context.Background(), f.st, "test", JobRequest{CrawlerID: "lab-1", Targets: []string{"127.0.0.1/32"}, Ports: []int{22}}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	resp := f.signedPoll(nil)
	var job protocol.Job
	_ = json.NewDecoder(resp.Body).Decode(&job)
	if resp.StatusCode != 200 || job.JobID != j.ID || job.ResultToken != protocol.EncodeKey(j.ResultToken) {
		t.Fatalf("poll: %d %+v", resp.StatusCode, job)
	}
	if c, _ := f.st.Crawler(context.Background(), "lab-1"); c.LastSeenAt == nil {
		t.Error("last_seen_at not updated")
	}

	other, _ := protocol.NewKey()
	cases := map[string]struct {
		mod  func(h http.Header, ts *int64, key *[]byte)
		want int
	}{
		"wrong key":        {func(_ http.Header, _ *int64, k *[]byte) { *k = other }, 401},
		"unknown crawler":  {func(h http.Header, _ *int64, _ *[]byte) { h.Set(protocol.HeaderCrawlerID, "lab-9") }, 401},
		"old timestamp":    {func(_ http.Header, ts *int64, _ *[]byte) { *ts -= 600 }, 401},
		"future timestamp": {func(_ http.Header, ts *int64, _ *[]byte) { *ts += 600 }, 401},
		"short nonce":      {func(h http.Header, _ *int64, _ *[]byte) { h.Set(protocol.HeaderRequestNonce, "abc") }, 401},
		"garbage hmac":     {func(h http.Header, _ *int64, _ *[]byte) { h.Set(protocol.HeaderRequestHMAC, "zz") }, 401},
		"replayed nonce": {func(h http.Header, _ *int64, _ *[]byte) {
			h.Set(protocol.HeaderRequestNonce, "fixed-nonce-0000000000")
		}, 0},
	}
	for name, c := range cases {
		resp := f.signedPoll(c.mod)
		if c.want != 0 && resp.StatusCode != c.want {
			t.Errorf("%s: %d, want %d", name, resp.StatusCode, c.want)
		}
	}
	if resp := f.signedPoll(cases["replayed nonce"].mod); resp.StatusCode != http.StatusConflict {
		t.Errorf("replayed nonce: %d, want 409", resp.StatusCode)
	}
}

func TestResultValidation(t *testing.T) {
	f := newFixture(t)
	j, _ := CreateJob(context.Background(), f.st, "test", JobRequest{CrawlerID: "lab-1", Targets: []string{"127.0.0.1/32"}, Ports: []int{22}}, f.now)
	if resp := f.signedPoll(nil); resp.StatusCode != 200 {
		t.Fatal("poll failed")
	}
	post := func(body string) int {
		nonce, _ := protocol.NewNonce()
		path := protocol.ResultPath(j.ID)
		ts := f.now.Unix()
		sig := protocol.Sign(j.ResultToken, protocol.SigningString("POST", path, "lab-1", j.ID, ts, nonce, []byte(body)))
		return f.do("POST", path, "application/json", body, func(r *http.Request) {
			r.Header.Set(protocol.HeaderCrawlerID, "lab-1")
			r.Header.Set(protocol.HeaderResultNonce, nonce)
			r.Header.Set(protocol.HeaderResultTimestamp, strconv.FormatInt(ts, 10))
			r.Header.Set(protocol.HeaderResultHMAC, sig)
		}).StatusCode
	}
	if got := post(`not json`); got != http.StatusBadRequest {
		t.Errorf("malformed body: %d, want 400", got)
	}
	if got := post(`{"job_id":"other","crawler_id":"lab-1"}`); got != http.StatusBadRequest {
		t.Errorf("mismatched job id: %d, want 400", got)
	}
	if got := post(`{"job_id":"` + j.ID + `","crawler_id":"lab-1","networks":[]}`); got != http.StatusCreated {
		t.Errorf("valid: %d, want 201", got)
	}
	if got := post(`{"job_id":"` + j.ID + `","crawler_id":"lab-1","networks":[]}`); got != http.StatusConflict {
		t.Errorf("second result: %d, want 409", got)
	}
	unsigned := f.do("POST", protocol.ResultPath(j.ID), "application/json", `{}`, nil)
	if unsigned.StatusCode != http.StatusUnauthorized {
		t.Errorf("unsigned: %d, want 401", unsigned.StatusCode)
	}
}

func TestHashPassword(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Error("short password accepted")
	}
	if _, err := HashPassword(strings.Repeat("x", 73)); err == nil {
		t.Error("password over 72 bytes accepted")
	}
}
