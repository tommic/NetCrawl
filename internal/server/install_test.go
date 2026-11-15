package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netcrawler/internal/agent"
	"netcrawler/internal/protocol"
	"netcrawler/internal/store/memstore"
	"netcrawler/internal/tlspin"
)

type installFixture struct {
	t      *testing.T
	st     *memstore.Store
	srv    *httptest.Server
	ic     *InstallConfig
	client *http.Client
	binSum string
}

func newInstallFixture(t *testing.T) *installFixture {
	t.Helper()
	f := &installFixture{t: t, st: memstore.New()}
	dir := t.TempDir()
	bin := []byte("#!/bin/sh\necho fake agent\n")
	if err := os.WriteFile(filepath.Join(dir, "netcrawl-agent-linux-amd64"), bin, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bin)
	f.binSum = hex.EncodeToString(sum[:])

	f.ic = &InstallConfig{AgentDir: dir}
	s := New(f.st, Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Install: f.ic, SecureCookies: true})
	f.srv = httptest.NewUnstartedServer(s.Handler())
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.ic.PublicURL = f.srv.URL
	f.ic.TLSPin = tlspin.Pin(f.srv.Certificate())
	if err := f.ic.Validate(); err != nil {
		t.Fatal(err)
	}
	tc, err := tlspin.ClientConfig(f.ic.TLSPin)
	if err != nil {
		t.Fatal(err)
	}
	f.client = &http.Client{Transport: &http.Transport{TLSClientConfig: tc, Proxy: nil}}

	hash, _ := HashPassword(testPassword)
	_ = f.st.SetAdmin(context.Background(), "admin", hash)
	if _, _, err := CreateCrawler(context.Background(), f.st, "test", CrawlerRequest{ID: "lab-1", Allow: []string{"127.0.0.0/29"}, MaxHosts: 8}, time.Now()); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *installFixture) get(path string) (int, string) {
	f.t.Helper()
	resp, err := f.client.Get(f.srv.URL + path)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// enroll creates an install command via the admin API and returns the code.
func (f *installFixture) enroll(cookie *http.Cookie) (EnrollmentView, string) {
	f.t.Helper()
	req, _ := http.NewRequest("POST", f.srv.URL+"/api/v1/admin/crawlers/lab-1/enroll", strings.NewReader(`{"reverse_dns":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(cookie)
	resp, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		f.t.Fatalf("enroll: %d %s", resp.StatusCode, b)
	}
	var v EnrollmentView
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		f.t.Fatal(err)
	}
	i := strings.Index(v.Command, "/install/")
	token := strings.SplitN(v.Command[i+len("/install/"):], "'", 2)[0]
	return v, token
}

func (f *installFixture) login() *http.Cookie {
	f.t.Helper()
	resp, err := f.client.Post(f.srv.URL+"/api/v1/admin/login", "application/json", strings.NewReader(`{"username":"admin","password":"`+testPassword+`"}`))
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookie {
			return c
		}
	}
	f.t.Fatalf("login: %d", resp.StatusCode)
	return nil
}

func TestInstallerFlow(t *testing.T) {
	f := newInstallFixture(t)
	ctx := context.Background()
	old, _ := f.st.Crawler(ctx, "lab-1")

	v, token := f.enroll(f.login())
	if !protocol.ValidToken(token) {
		t.Fatalf("token %q", token)
	}
	wantCmd := "curl -fsSL -k --pinnedpubkey '" + f.ic.TLSPin + "' '" + f.srv.URL + "/install/" + token + "' | sudo sh"
	if v.Command != wantCmd {
		t.Fatalf("command\n got %s\nwant %s", v.Command, wantCmd)
	}
	if d := time.Until(v.ExpiresAt); d < 29*time.Minute || d > 31*time.Minute {
		t.Fatalf("expires in %v", d)
	}

	// The script carries server, pin, code and checksum and is valid sh.
	code, script := f.get("/install/" + token)
	if code != 200 {
		t.Fatalf("script: %d", code)
	}
	for _, want := range []string{"SERVER_URL='" + f.srv.URL + "'", "TLS_PIN='" + f.ic.TLSPin + "'", "NETCRAWL_ENROLL_TOKEN='" + token + "'", "SHA256_AMD64='" + f.binSum + "'", "SHA256_ARM64=''", `CRAWLER_ID='lab-1'`} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %s", want)
		}
	}
	if sh, err := exec.LookPath("sh"); err == nil {
		cmd := exec.Command(sh, "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("sh -n: %v %s", err, out)
		}
	}
	if code, _ := f.get("/install/" + strings.Repeat("A", 43)); code != 404 {
		t.Fatalf("unknown code: %d", code)
	}
	if code, _ := f.get("/install/not-a-token"); code != 404 {
		t.Fatalf("bad code: %d", code)
	}

	// Binaries.
	if code, body := f.get("/install/agent/linux-amd64"); code != 200 || !strings.Contains(body, "fake agent") {
		t.Fatalf("amd64: %d", code)
	}
	for _, p := range []string{"/install/agent/linux-arm64", "/install/agent/linux-mips", "/install/agent/netcrawl-agent-linux-amd64", "/install/agent/linux-..%2fx"} {
		if code, _ := f.get(p); code != 404 {
			t.Errorf("%s: %d", p, code)
		}
	}
	if code, body := f.get("/install/uninstall"); code != 200 || !strings.Contains(body, "userdel") {
		t.Fatalf("uninstall: %d", code)
	}

	// A wrong pin fails before the code is sent: the code stays valid.
	dir := t.TempDir()
	wrongPin := "sha256//" + strings.Repeat("A", 43) + "="
	if _, err := agent.Enroll(ctx, agent.EnrollOptions{ServerURL: f.srv.URL, Token: token, TLSPin: wrongPin, ConfigDir: dir}); err == nil || !strings.Contains(err.Error(), "pin") {
		t.Fatalf("wrong pin: %v", err)
	}
	if code, _ := f.get("/install/" + token); code != 200 {
		t.Fatal("code consumed by a failed TLS handshake")
	}

	// Enroll with the right pin.
	cfg, err := agent.Enroll(ctx, agent.EnrollOptions{ServerURL: f.srv.URL, Token: token, TLSPin: f.ic.TLSPin, ConfigDir: dir, StateDir: filepath.Join(dir, "state")})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CrawlerID != "lab-1" || cfg.Limits.MaxHosts != 8 || strings.Join(cfg.Limits.Allow, ",") != "127.0.0.0/29" || !cfg.ReverseDNS || cfg.TLSPin != f.ic.TLSPin {
		t.Fatalf("config %+v", cfg)
	}
	info, err := os.Stat(filepath.Join(dir, "agent.secret"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("secret file: %v %v", info, err)
	}
	loaded, err := agent.LoadConfig(filepath.Join(dir, "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.LockFile != filepath.Join(dir, "state", "agent.lock") {
		t.Fatalf("lock file %s", loaded.LockFile)
	}
	now, _ := f.st.Crawler(ctx, "lab-1")
	if bytes.Equal(now.Secret, old.Secret) {
		t.Fatal("secret not rotated")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "agent.secret"))
	if k, _ := protocol.DecodeKey(string(raw)); !bytes.Equal(k, now.Secret) {
		t.Fatal("agent secret differs from server")
	}

	// The code works once.
	if _, err := agent.Enroll(ctx, agent.EnrollOptions{ServerURL: f.srv.URL, Token: token, TLSPin: f.ic.TLSPin, ConfigDir: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("second enroll: %v", err)
	}
	if code, _ := f.get("/install/" + token); code != 404 {
		t.Fatal("script still served after use")
	}
	// Existing config is not overwritten without --force.
	_, token2 := f.enroll(f.login())
	if _, err := agent.Enroll(ctx, agent.EnrollOptions{ServerURL: f.srv.URL, Token: token2, TLSPin: f.ic.TLSPin, ConfigDir: dir}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrite: %v", err)
	}

	audit, _ := f.st.ListAudit(ctx, 20)
	var actions []string
	for _, a := range audit {
		actions = append(actions, a.Action)
	}
	joined := strings.Join(actions, ",")
	for _, want := range []string{"crawler.enrollment.create", "crawler.enroll", "crawler.enroll.failed"} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit lacks %s: %s", want, joined)
		}
	}
}

func TestInstallerDisabled(t *testing.T) {
	f := newFixture(t)
	c := f.login()
	resp := f.do("POST", "/api/v1/admin/crawlers/lab-1/enroll", "application/json", `{}`, func(r *http.Request) { r.AddCookie(c) })
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("enroll without public URL: %d", resp.StatusCode)
	}
	if resp := f.do("GET", "/install/"+strings.Repeat("A", 43), "", "", nil); resp.StatusCode != 404 {
		t.Fatalf("script: %d", resp.StatusCode)
	}
}

func TestInstallConfigValidate(t *testing.T) {
	pin := "sha256//" + strings.Repeat("A", 43) + "="
	cases := map[InstallConfig]bool{
		{PublicURL: "https://192.168.1.5:8443", TLSPin: pin}:    true,
		{PublicURL: "https://netcrawl.example.org"}:             true,
		{PublicURL: "http://127.0.0.1:8080"}:                    true,
		{PublicURL: "http://192.168.1.5:8080"}:                  false,
		{PublicURL: "https://192.168.1.5/x"}:                    false,
		{PublicURL: "https://192.168.1.5", TLSPin: "sha256//x"}: false,
		{PublicURL: "http://127.0.0.1:8080", TLSPin: pin}:       false,
		{PublicURL: "https://a'b"}:                              false,
		{PublicURL: ""}:                                         false,
	}
	for c, ok := range cases {
		if err := c.Validate(); (err == nil) != ok {
			t.Errorf("%+v: err = %v, want ok=%v", c, err, ok)
		}
	}
}

func TestDisableCrawler(t *testing.T) {
	f := newFixture(t)
	c := f.login()
	put := func(body string) *http.Response {
		return f.do("PUT", "/api/v1/admin/crawlers/lab-1", "application/json", body, func(r *http.Request) { r.AddCookie(c) })
	}
	if resp := put(`{}`); resp.StatusCode != 400 {
		t.Fatalf("empty update: %d", resp.StatusCode)
	}
	if resp := f.do("PUT", "/api/v1/admin/crawlers/nope", "application/json", `{"enabled":false}`, func(r *http.Request) { r.AddCookie(c) }); resp.StatusCode != 400 {
		t.Fatalf("unknown crawler: %d", resp.StatusCode)
	}
	if resp := put(`{"enabled":false}`); resp.StatusCode != 200 {
		t.Fatalf("disable: %d", resp.StatusCode)
	}
	got, _ := f.st.Crawler(context.Background(), "lab-1")
	if got.Enabled {
		t.Fatal("still enabled")
	}
	if resp := put(`{"enabled":true}`); resp.StatusCode != 200 {
		t.Fatalf("enable: %d", resp.StatusCode)
	}
}
