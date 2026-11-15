// Package e2e holds the acceptance tests of the loopback-only pilot
// (docs/E2E-ABNAHME.md, cases E2E-01 to E2E-07).
//
// Server and agent run in-process against each other over real HTTP on
// 127.0.0.1. Every HTTP request of the agent and every scan connection
// attempt is recorded; the only scan target that may ever be contacted is
// a listener on 127.0.0.1 started by the test.
//
// Set NETCRAWL_E2E_REPORT=<file> to write the acceptance evidence
// (Markdown). Set NETCRAWL_TEST_DATABASE_URL to run against PostgreSQL
// instead of the in-memory store (the database is wiped).
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netcrawler/internal/agent"
	"netcrawler/internal/protocol"
	"netcrawler/internal/server"
	"netcrawler/internal/store"
	"netcrawler/internal/store/memstore"
	"netcrawler/internal/store/pgstore"
	"netcrawler/internal/version"
)

// ---- evidence ----

type evidence struct {
	ID       string
	Case     string
	Time     time.Time
	Store    string
	Requests []string
	Connects []string
	Result   string
	Proof    []string
	Passed   bool
}

var (
	evidenceMu sync.Mutex
	report     []*evidence
)

func TestMain(m *testing.M) {
	code := m.Run()
	if path := os.Getenv("NETCRAWL_E2E_REPORT"); path != "" {
		if err := writeReport(path); err != nil {
			fmt.Fprintf(os.Stderr, "write E2E report: %v\n", err)
			if code == 0 {
				code = 1
			}
		}
	}
	os.Exit(code)
}

func writeReport(path string) error {
	evidenceMu.Lock()
	defer evidenceMu.Unlock()
	sort.SliceStable(report, func(i, j int) bool { return report[i].ID < report[j].ID })
	var b strings.Builder
	fmt.Fprintf(&b, "# E2E-Abnahmebeleg: Loopback-Pilot\n\n")
	fmt.Fprintf(&b, "- Erzeugt: %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- Build-/Versionskennung: `%s`\n", version.Version)
	if len(report) > 0 {
		fmt.Fprintf(&b, "- Datenhaltung: %s\n", report[0].Store)
	}
	fmt.Fprintf(&b, "- Erlaubtes Scan-Ziel: `%s`, `max_hosts: 1`\n", "127.0.0.1/32")
	fmt.Fprintf(&b, "- Job-IDs und Nonces sind anonymisiert (`<job>`).\n\n")
	all := true
	for _, e := range report {
		all = all && e.Passed
	}
	if all {
		fmt.Fprintf(&b, "**Gesamtergebnis: alle %d Testfälle bestanden.**\n\n", len(report))
	} else {
		fmt.Fprintf(&b, "**Gesamtergebnis: NICHT bestanden.**\n\n")
	}
	fmt.Fprintf(&b, "| ID | Fall | Ergebnis |\n|---|---|---|\n")
	for _, e := range report {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", e.ID, e.Case, passText(e.Passed))
	}
	for _, e := range report {
		fmt.Fprintf(&b, "\n## %s – %s\n\n", e.ID, e.Case)
		fmt.Fprintf(&b, "- Testzeit: %s\n", e.Time.UTC().Format(time.RFC3339))
		fmt.Fprintf(&b, "- Ergebnis: **%s** – %s\n", passText(e.Passed), e.Result)
		fmt.Fprintf(&b, "- HTTP-Requests an die Crawler-API ([Quelle] Methode Pfad → Status):\n")
		if len(e.Requests) == 0 {
			fmt.Fprintf(&b, "  - keine\n")
		}
		for _, r := range e.Requests {
			fmt.Fprintf(&b, "  - `%s`\n", r)
		}
		fmt.Fprintf(&b, "- Tatsächliche Zieladressen (TCP-Connects):\n")
		if len(e.Connects) == 0 {
			fmt.Fprintf(&b, "  - keine\n")
		}
		for _, c := range e.Connects {
			fmt.Fprintf(&b, "  - `%s`\n", c)
		}
		if len(e.Proof) > 0 {
			fmt.Fprintf(&b, "- Nachweise:\n")
			for _, p := range e.Proof {
				fmt.Fprintf(&b, "  - %s\n", p)
			}
		}
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func passText(ok bool) string {
	if ok {
		return "bestanden"
	}
	return "NICHT bestanden"
}

// ---- recording ----

var jobIDRe = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// sourceHeader marks requests the test sends itself (not the agent). The
// recorder strips it before forwarding.
const sourceHeader = "X-E2E-Source"

type recordedRequest struct {
	Source string
	Method string
	URL    string
	Header http.Header
	Body   []byte
	Status int
}

// recorder is an http.RoundTripper that records every request and can
// tamper with request bodies after they were signed.
type recorder struct {
	base   http.RoundTripper
	mu     sync.Mutex
	reqs   []recordedRequest
	mutate func(r *http.Request, body []byte) []byte
}

func (rec *recorder) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		r.Body.Close()
	}
	source := "Crawler"
	if r.Header.Get(sourceHeader) != "" {
		source = "Test, manuell"
		r.Header.Del(sourceHeader)
	}
	if rec.mutate != nil {
		body = rec.mutate(r, body)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	resp, err := rec.base.RoundTrip(r)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	rec.mu.Lock()
	rec.reqs = append(rec.reqs, recordedRequest{source, r.Method, r.URL.String(), r.Header.Clone(), body, status})
	rec.mu.Unlock()
	return resp, err
}

func (rec *recorder) all() []recordedRequest {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	return append([]recordedRequest(nil), rec.reqs...)
}

func (rec *recorder) countAgent(method string) int {
	n := 0
	for _, r := range rec.all() {
		if r.Method == method && r.Source == "Crawler" {
			n++
		}
	}
	return n
}

func describe(r recordedRequest) string {
	path := r.URL
	if i := strings.Index(path, "/api/"); i >= 0 {
		path = path[i:]
	}
	return fmt.Sprintf("[%s] %s %s → %d", r.Source, r.Method, jobIDRe.ReplaceAllString(path, "<job>"), r.Status)
}

// dialRecorder records every scan connection attempt. It refuses
// (without connecting) anything outside 127.0.0.0/8, as a last safety net.
type dialRecorder struct {
	mu    sync.Mutex
	addrs []string
}

func (d *dialRecorder) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	d.addrs = append(d.addrs, address)
	d.mu.Unlock()
	host, _, err := net.SplitHostPort(address)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() || ip.To4() == nil {
		return nil, fmt.Errorf("e2e safety net: refusing connection to %s", address)
	}
	var nd net.Dialer
	return nd.DialContext(ctx, network, address)
}

func (d *dialRecorder) all() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

// ---- environment ----

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type env struct {
	t        *testing.T
	ev       *evidence
	st       store.Store
	srvClock *clock
	agClock  *clock
	url      string
	secret   []byte
	dir      string
	rec      *recorder
	dials    *dialRecorder
	openPort int
	agent    *agent.Agent
	admin    *http.Client
	server   *server.Server
	allow    []string
	maxHosts int
}

const (
	crawlerID     = "pilot-1"
	adminPassword = "e2e-admin-password-123"
)

// adminCreateJob creates a job through the admin HTTP API (login with
// session cookie) and returns the HTTP status.
func (e *env) adminCreateJob(targets []string, ports []int, maxHosts int) int {
	e.t.Helper()
	if e.admin == nil {
		jar := &cookieJar{}
		e.admin = &http.Client{Jar: jar}
		resp, err := e.admin.Post(e.url+"/api/v1/admin/login", "application/json",
			strings.NewReader(`{"username":"admin","password":"`+adminPassword+`"}`))
		if err != nil {
			e.t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			e.t.Fatalf("admin login: %d", resp.StatusCode)
		}
	}
	body, _ := json.Marshal(server.JobRequest{CrawlerID: crawlerID, Targets: targets, Ports: ports, MaxHosts: maxHosts})
	resp, err := e.admin.Post(e.url+"/api/v1/admin/jobs", "application/json", bytes.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func newStore(t *testing.T) (store.Store, string) {
	url := os.Getenv("NETCRAWL_TEST_DATABASE_URL")
	if url == "" {
		return memstore.New(), "In-Memory-Store"
	}
	ctx := context.Background()
	s, err := pgstore.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	return s, "PostgreSQL"
}

func setup(t *testing.T, id, name string) *env {
	t.Helper()
	return setupCrawler(t, id, name, []string{"127.0.0.1/32"}, 1)
}

// setupCrawler is setup with a crawler released for allow/maxHosts.
func setupCrawler(t *testing.T, id, name string, allow []string, maxHosts int) *env {
	t.Helper()
	st, storeName := newStore(t)
	e := &env{
		t:        t,
		st:       st,
		srvClock: &clock{now: time.Now().UTC().Truncate(time.Second)},
		dir:      t.TempDir(),
		dials:    &dialRecorder{},
		allow:    allow,
		maxHosts: maxHosts,
	}
	e.agClock = &clock{now: e.srvClock.Now()}
	e.ev = &evidence{ID: id, Case: name, Time: time.Now(), Store: storeName}
	evidenceMu.Lock()
	report = append(report, e.ev)
	evidenceMu.Unlock()
	t.Cleanup(func() {
		e.ev.Passed = !t.Failed()
		for _, r := range e.rec.all() {
			e.ev.Requests = append(e.ev.Requests, describe(r))
		}
		e.ev.Connects = append(e.ev.Connects, e.dials.all()...)
	})

	srv := server.New(st, server.Options{Now: e.srvClock.Now, Logger: discardLogger()})
	e.server = srv
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	e.url = hs.URL

	hash, err := server.HashPassword(adminPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetAdmin(context.Background(), "admin", hash); err != nil {
		t.Fatal(err)
	}
	e.rec = &recorder{base: http.DefaultTransport}

	_, secret, err := server.CreateCrawler(context.Background(), st, "e2e", server.CrawlerRequest{
		ID: crawlerID, Allow: allow, MaxHosts: maxHosts,
	}, e.srvClock.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.secret, _ = protocol.DecodeKey(secret)
	if err := os.WriteFile(filepath.Join(e.dir, "agent.secret"), []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	e.openPort = ln.Addr().(*net.TCPAddr).Port
	return e
}

func (e *env) writeConfig(interval int) string {
	cfg := map[string]any{
		"version":     1,
		"crawler_id":  crawlerID,
		"server_url":  e.url,
		"secret_file": "agent.secret",
		"polling":     map[string]int{"interval_seconds": interval},
		"limits":      map[string]any{"allow": e.allow, "max_hosts": e.maxHosts},
		"lock_file":   "agent.lock",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	path := filepath.Join(e.dir, "agent.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		e.t.Fatal(err)
	}
	return path
}

// startAgent loads the config and creates the agent wired to the recorders.
func (e *env) startAgent() *agent.Agent {
	e.t.Helper()
	cfg, err := agent.LoadConfig(e.writeConfig(60))
	if err != nil {
		e.t.Fatal(err)
	}
	a, err := agent.New(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { a.Close() })
	a.HTTP = &http.Client{
		Transport:     e.rec,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	a.Dial = e.dials.Dial
	a.Now = e.agClock.Now
	e.agent = a
	return a
}

func (e *env) createJob(ports []int, ttl time.Duration) store.Job {
	e.t.Helper()
	j, err := server.CreateJob(context.Background(), e.st, "e2e", server.JobRequest{
		CrawlerID: crawlerID, Targets: []string{"127.0.0.1/32"}, Ports: ports, TTLSeconds: int(ttl.Seconds()),
	}, e.srvClock.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	return j
}

// injectJob stores a job directly, bypassing the server-side checks. It
// simulates a compromised or misconfigured server.
func (e *env) injectJob(targets []string, maxHosts int) store.Job {
	e.t.Helper()
	id, _ := protocol.NewID()
	token, _ := protocol.NewKey()
	now := e.srvClock.Now()
	j := store.Job{
		ID: id, CrawlerID: crawlerID, Targets: targets, Ports: []int{e.openPort}, MaxHosts: maxHosts,
		TimeoutMs: 500, ResultToken: token, Status: store.JobPending, CreatedBy: "e2e-injected",
		CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	if err := e.st.CreateJob(context.Background(), j); err != nil {
		e.t.Fatal(err)
	}
	return j
}

func (e *env) proof(format string, args ...any) {
	e.ev.Proof = append(e.ev.Proof, fmt.Sprintf(format, args...))
}

func (e *env) jobStatus(id string) string {
	j, err := e.st.Job(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return j.Status
}

// requireNoConnectNoPost asserts the evidence for every rejection case:
// no scan connection and no result POST by the agent so far.
func (e *env) requireNoConnectNoPost(label string) {
	e.t.Helper()
	if d := e.dials.all(); len(d) != 0 {
		e.t.Errorf("expected no connection attempts, got %v", d)
	}
	if n := e.rec.countAgent(http.MethodPost); n != 0 {
		e.t.Errorf("expected no result POST, got %d", n)
	}
	e.proof("%sKein TCP-Connect: der aufgezeichnete Dialer hat 0 Verbindungsversuche registriert.", label)
	e.proof("%sKein Ergebnis-POST des Crawlers: der aufgezeichnete HTTP-Transport hat 0 POST-Requests des Crawlers registriert.", label)
}

func discardLogger() *slogLogger { return newDiscardLogger() }

// ---- test cases ----

func TestE2E01ValidJob(t *testing.T) {
	e := setup(t, "E2E-01", "Gültiger Job, TTL 5 min, 127.0.0.1/32, max_hosts 1")
	a := e.startAgent()
	closed := closedPort(t)
	j := e.createJob([]int{e.openPort, closed}, 5*time.Minute)

	out, err := a.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Rejected != "" || out.ResultStatus != http.StatusCreated {
		t.Fatalf("outcome = %+v, want result 201", out)
	}
	for _, d := range e.dials.all() {
		if !strings.HasPrefix(d, "127.0.0.1:") {
			t.Errorf("connection outside loopback: %s", d)
		}
	}
	if n := len(e.dials.all()); n != 2 {
		t.Errorf("connection attempts = %d, want 2 (one per port)", n)
	}
	if s := e.jobStatus(j.ID); s != store.JobCompleted {
		t.Errorf("job status = %s, want completed", s)
	}
	res, err := e.st.Result(context.Background(), j.ID)
	if err != nil {
		t.Fatal(err)
	}
	var r protocol.Result
	if err := json.Unmarshal(res.Body, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Networks) != 1 || len(r.Networks[0].Hosts["127.0.0.1"].Ports) != 1 || r.Networks[0].Hosts["127.0.0.1"].Ports[0] != e.openPort {
		t.Errorf("stored result = %s", res.Body)
	}
	e.ev.Result = "TCP-Prüfung nur gegen 127.0.0.1, signiertes Ergebnis mit 201 angenommen."
	e.proof("Job-Status nach Annahme: `%s`; gespeichertes Ergebnis enthält 127.0.0.1 mit offenem Test-Port.", store.JobCompleted)
	e.proof("Alle Verbindungsversuche gingen an 127.0.0.1 (ein offener und ein geschlossener Test-Port).")
}

func TestE2E02TamperedBody(t *testing.T) {
	e := setup(t, "E2E-02", "Ergebnisbody nach HMAC-Bildung verändert")
	a := e.startAgent()
	j := e.createJob([]int{e.openPort}, 5*time.Minute)
	e.rec.mutate = func(r *http.Request, body []byte) []byte {
		if r.Method != http.MethodPost {
			return body
		}
		// Change the content after signing, keeping valid JSON.
		return bytes.Replace(body, []byte(`"agent_version":"`), []byte(`"agent_version":"x`), 1)
	}
	out, err := a.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected the tampered result to be rejected")
	}
	if out.ResultStatus != http.StatusUnauthorized && out.ResultStatus != http.StatusForbidden {
		t.Fatalf("status = %d, want 401 or 403", out.ResultStatus)
	}
	if s := e.jobStatus(j.ID); s == store.JobCompleted {
		t.Error("tampered result must not complete the job")
	}
	if _, err := e.st.Result(context.Background(), j.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("tampered result was stored: %v", err)
	}
	e.ev.Result = fmt.Sprintf("Server lehnt mit %d ab.", out.ResultStatus)
	e.proof("Der Body wurde nach der Signatur im Transport verändert (`agent_version`), die Signatur blieb unverändert.")
	e.proof("Kein Ergebnis gespeichert, Job-Status bleibt `%s`.", e.jobStatus(j.ID))
}

func TestE2E03Replay(t *testing.T) {
	e := setup(t, "E2E-03", "Identisches Ergebnis erneut abgeben")
	a := e.startAgent()
	j := e.createJob([]int{e.openPort}, 5*time.Minute)
	out, err := a.RunOnce(context.Background())
	if err != nil || out.ResultStatus != http.StatusCreated {
		t.Fatalf("first submission: %+v %v", out, err)
	}
	var original recordedRequest
	for _, r := range e.rec.all() {
		if r.Method == http.MethodPost {
			original = r
		}
	}
	req, _ := http.NewRequest(original.Method, original.URL, bytes.NewReader(original.Body))
	req.Header = original.Header.Clone()
	req.Header.Set(sourceHeader, "manual")
	resp, err := (&http.Client{Transport: e.rec}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("replay status = %d, want 409", resp.StatusCode)
	}
	audit, _ := e.st.ListAudit(context.Background(), 100)
	accepted := 0
	for _, a := range audit {
		if a.Action == "result.accepted" {
			accepted++
		}
	}
	if accepted != 1 {
		t.Errorf("accepted results = %d, want 1", accepted)
	}
	_ = j
	e.ev.Result = "Wiederholte, bitgleiche Abgabe (gleiche Header inkl. Nonce und HMAC, gleicher Body) wird mit 409 Replay abgelehnt."
	e.proof("Genau ein Ergebnis angenommen (Audit-Log: 1 × `result.accepted`).")
}

func TestE2E04Expired(t *testing.T) {
	e := setup(t, "E2E-04", "Bereits abgelaufener Job")
	a := e.startAgent()

	// Part 1: the job expires between delivery and execution. The agent
	// must refuse it locally.
	j := e.createJob([]int{e.openPort}, time.Minute)
	e.agClock.Add(2 * time.Minute)
	out, err := a.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.JobID != j.ID || !strings.Contains(out.Rejected, "expired") {
		t.Fatalf("outcome = %+v, want local rejection as expired", out)
	}
	e.requireNoConnectNoPost("Teil 1: ")

	// Part 2: a correctly signed result for an expired job gets 410.
	j2 := e.createJob([]int{e.openPort}, time.Minute)
	job := e.fetchJobManually()
	if job.JobID != j2.ID {
		t.Fatalf("fetched %s, want %s", job.JobID, j2.ID)
	}
	e.srvClock.Add(2 * time.Minute)
	status := e.postResultManually(job, e.srvClock.Now())
	if status != http.StatusGone {
		t.Fatalf("expired result status = %d, want 410", status)
	}
	e.ev.Result = "Crawler lehnt den abgelaufenen Job lokal ab (kein Connect, kein POST); Server beantwortet ein signiertes Ergebnis zu einem abgelaufenen Job mit 410."
	e.proof("Teil 1: Job-TTL 1 min, Crawler-Uhr 2 min später → lokale Ablehnung „%s“.", out.Rejected)
	e.proof("Teil 2: Ergebnis manuell korrekt signiert (ohne Scan) nach Ablauf eingereicht → 410 Expired.")
}

func TestE2E05OutOfScope(t *testing.T) {
	e := setup(t, "E2E-05", "127.0.0.2/32, privates Netz oder nicht erlaubtes Ziel")
	a := e.startAgent()
	for _, target := range []string{"127.0.0.2/32", "192.168.1.10/32", "10.0.0.0/8", "127.0.0.0/8"} {
		// The server refuses to create such jobs ...
		status := e.adminCreateJob([]string{target}, []int{e.openPort}, 1)
		if status != http.StatusBadRequest {
			t.Errorf("admin API status for %s = %d, want 400", target, status)
		}
		// ... and the agent refuses them even if a server delivers them.
		j := e.injectJob([]string{target}, 1)
		out, err := a.RunOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if out.JobID != j.ID || out.Rejected == "" {
			t.Fatalf("%s: outcome = %+v, want local rejection", target, out)
		}
		e.proof("`%s`: Admin-API `POST /api/v1/admin/jobs` verweigert die Job-Anlage mit %d; ein direkt in die Datenbank geschriebener Job (simulierter kompromittierter Server) wird vom Crawler lokal abgelehnt („%s“).", target, status, out.Rejected)
	}
	e.requireNoConnectNoPost("")
	e.ev.Result = "Lokale Ablehnung vor jedem Connect und POST."
}

func TestE2E06AboveMaxHosts(t *testing.T) {
	e := setup(t, "E2E-06", "Scope oberhalb von max_hosts: 1")
	a := e.startAgent()
	cases := []struct {
		targets  []string
		maxHosts int
	}{
		{[]string{"127.0.0.1/32"}, 2},
		{[]string{"127.0.0.0/30"}, 4},
		{[]string{"127.0.0.1/32", "127.0.0.2/32"}, 2},
	}
	for _, c := range cases {
		status := e.adminCreateJob(c.targets, []int{e.openPort}, c.maxHosts)
		if status != http.StatusBadRequest {
			t.Errorf("admin API status for %v max_hosts %d = %d, want 400", c.targets, c.maxHosts, status)
		}
		j := e.injectJob(c.targets, c.maxHosts)
		out, err := a.RunOnce(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if out.JobID != j.ID || out.Rejected == "" {
			t.Fatalf("%v/%d: outcome = %+v, want local rejection", c.targets, c.maxHosts, out)
		}
		e.proof("Targets `%s`, `max_hosts: %d`: Admin-API verweigert mit %d; direkt in die Datenbank geschriebener Job vom Crawler lokal abgelehnt („%s“).", strings.Join(c.targets, ", "), c.maxHosts, status, out.Rejected)
	}
	e.requireNoConnectNoPost("")
	e.ev.Result = "Lokale Ablehnung vor jedem Connect und POST."
}

func TestE2E07PollInterval(t *testing.T) {
	e := setup(t, "E2E-07", "polling.interval_seconds < 60")
	for _, interval := range []int{59, 0, -1} {
		_, err := agent.LoadConfig(e.writeConfig(interval))
		if err == nil || !strings.Contains(err.Error(), "interval_seconds") {
			t.Errorf("interval %d: err = %v, want config error", interval, err)
		}
	}
	if _, err := agent.LoadConfig(e.writeConfig(60)); err != nil {
		t.Errorf("interval 60 must be accepted: %v", err)
	}
	if n := len(e.rec.all()); n != 0 {
		t.Errorf("expected no requests, got %d", n)
	}
	if d := e.dials.all(); len(d) != 0 {
		t.Errorf("expected no connections, got %v", d)
	}
	e.ev.Result = "Config-Load schlägt fehl; kein Polling, kein Connect, kein POST."
	e.proof("Werte 59, 0 und −1 werden beim Laden abgelehnt, 60 wird akzeptiert.")
	e.proof("Kein HTTP-Request (Polling oder POST) und kein Verbindungsversuch aufgezeichnet.")
}

// TestPreflightLock covers "kein bereits laufender Crawl": a second agent
// with the same lock file fails before any network access.
func TestPreflightLock(t *testing.T) {
	e := setup(t, "V-01", "Vorabvalidierung: kein bereits laufender Crawl")
	e.startAgent()
	cfg, err := agent.LoadConfig(e.writeConfig(60))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.New(cfg); !errors.Is(err, agent.ErrLocked) {
		t.Fatalf("second agent: err = %v, want ErrLocked", err)
	}
	if n := len(e.rec.all()); n != 0 {
		t.Errorf("expected no requests, got %d", n)
	}
	e.ev.Result = "Zweiter Crawler-Start mit derselben Lock-Datei bricht vor jedem Netzwerkzugriff ab."
	e.proof("Kein HTTP-Request und kein Verbindungsversuch aufgezeichnet.")
}

// ---- helpers for manual requests ----

func (e *env) fetchJobManually() protocol.Job {
	e.t.Helper()
	nonce, _ := protocol.NewNonce()
	ts := e.srvClock.Now().Unix()
	req, _ := http.NewRequest(http.MethodGet, e.url+protocol.PathJob, nil)
	req.Header.Set(sourceHeader, "manual")
	req.Header.Set(protocol.HeaderCrawlerID, crawlerID)
	req.Header.Set(protocol.HeaderRequestNonce, nonce)
	req.Header.Set(protocol.HeaderRequestTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(protocol.HeaderRequestHMAC, protocol.Sign(e.secret, protocol.SigningString("GET", protocol.PathJob, crawlerID, "", ts, nonce, nil)))
	resp, err := (&http.Client{Transport: e.rec}).Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		e.t.Fatalf("manual poll: %d", resp.StatusCode)
	}
	var j protocol.Job
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		e.t.Fatal(err)
	}
	return j
}

func (e *env) postResultManually(job protocol.Job, now time.Time) int {
	e.t.Helper()
	token, err := protocol.DecodeKey(job.ResultToken)
	if err != nil {
		e.t.Fatal(err)
	}
	body, _ := json.Marshal(protocol.Result{JobID: job.JobID, CrawlerID: crawlerID, AgentVersion: "manual", Started: now, Finished: now})
	nonce, _ := protocol.NewNonce()
	path := protocol.ResultPath(job.JobID)
	ts := now.Unix()
	req, _ := http.NewRequest(http.MethodPost, e.url+path, bytes.NewReader(body))
	req.Header.Set(sourceHeader, "manual")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(protocol.HeaderCrawlerID, crawlerID)
	req.Header.Set(protocol.HeaderResultNonce, nonce)
	req.Header.Set(protocol.HeaderResultTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(protocol.HeaderResultHMAC, protocol.Sign(token, protocol.SigningString("POST", path, crawlerID, job.JobID, ts, nonce, body)))
	resp, err := (&http.Client{Transport: e.rec}).Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

// TestRejectsMalformedJobID: a server-supplied job_id ends up in the result
// URL, so the agent refuses anything but a UUID (no connect, no POST).
func TestRejectsMalformedJobID(t *testing.T) {
	e := setup(t, "V-02", "Job mit manipulierter job_id (Pfad-Injektion)")
	a := e.startAgent()
	// Serve a crafted job from a fake server instead of the real one.
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, _ := protocol.NewKey()
		_ = json.NewEncoder(w).Encode(protocol.Job{
			JobID: "../../admin/jobs", CrawlerID: crawlerID, ExpiresAt: e.agClock.Now().Add(time.Minute),
			Targets: []string{"127.0.0.1/32"}, MaxHosts: 1, Ports: []int{e.openPort}, TimeoutMs: 500,
			ResultToken: protocol.EncodeKey(token),
		})
	}))
	t.Cleanup(fake.Close)
	e.rec.base = rewriteTo(fake.URL)
	out, err := a.RunOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.Rejected, "invalid job_id") {
		t.Fatalf("outcome = %+v, want rejection", out)
	}
	e.requireNoConnectNoPost("")
	e.ev.Result = "Crawler lehnt eine job_id ab, die keine UUID ist, bevor sie in einen URL-Pfad gelangt."
}

// rewriteTo sends every request to base instead of its original host.
func rewriteTo(base string) http.RoundTripper {
	return roundTripFunc(func(r *http.Request) (*http.Response, error) {
		u, _ := http.NewRequest(r.Method, base+r.URL.Path, r.Body)
		u.Header = r.Header
		return http.DefaultTransport.RoundTrip(u)
	})
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
