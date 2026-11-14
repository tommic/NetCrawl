package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netcrawler/internal/protocol"
)

func writeAgentFiles(t *testing.T, mutate func(m map[string]any), secretMode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	key, _ := protocol.NewKey()
	if err := os.WriteFile(filepath.Join(dir, "agent.secret"), []byte(protocol.EncodeKey(key)), secretMode); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(dir, "agent.secret"), secretMode)
	m := map[string]any{
		"version":     1,
		"crawler_id":  "pilot-1",
		"server_url":  "http://127.0.0.1:8080",
		"secret_file": "agent.secret",
		"polling":     map[string]int{"interval_seconds": 60},
		"limits":      map[string]any{"allow": []string{"127.0.0.1/32"}, "max_hosts": 1},
		"lock_file":   "agent.lock",
	}
	if mutate != nil {
		mutate(m)
	}
	data, _ := json.Marshal(m)
	path := filepath.Join(dir, "agent.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigValid(t *testing.T) {
	cfg, err := LoadConfig(writeAgentFiles(t, nil, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.secret) != protocol.KeySize {
		t.Error("secret not loaded")
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := New(cfg); err != ErrLocked {
		t.Errorf("second New: %v, want ErrLocked", err)
	}
	a.Close()
	b, err := New(cfg)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	b.Close()
}

func TestLoadConfigErrors(t *testing.T) {
	cases := map[string]struct {
		mutate func(m map[string]any)
		want   string
	}{
		"version":        {func(m map[string]any) { m["version"] = 2 }, "version"},
		"crawler id":     {func(m map[string]any) { delete(m, "crawler_id") }, "crawler_id"},
		"interval":       {func(m map[string]any) { m["polling"] = map[string]int{"interval_seconds": 30} }, "interval_seconds"},
		"http remote":    {func(m map[string]any) { m["server_url"] = "http://192.168.1.5:8080" }, "https"},
		"url path":       {func(m map[string]any) { m["server_url"] = "https://srv.example/api" }, "plain"},
		"url scheme":     {func(m map[string]any) { m["server_url"] = "ftp://127.0.0.1" }, "scheme"},
		"wide allowlist": {func(m map[string]any) { m["limits"] = map[string]any{"allow": []string{"127.0.0.0/8"}, "max_hosts": 1} }, "loopback pilot"},
		"lan allowlist": {func(m map[string]any) {
			m["limits"] = map[string]any{"allow": []string{"192.168.1.0/24"}, "max_hosts": 1}
		}, "loopback pilot"},
		"max hosts": {func(m map[string]any) {
			m["limits"] = map[string]any{"allow": []string{"127.0.0.1/32"}, "max_hosts": 2}
		}, "loopback pilot"},
		"no lock":        {func(m map[string]any) { m["lock_file"] = "" }, "lock_file"},
		"unknown key":    {func(m map[string]any) { m["scan_everything"] = true }, "unknown field"},
		"missing secret": {func(m map[string]any) { m["secret_file"] = "missing" }, "secret_file"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadConfig(writeAgentFiles(t, c.mutate, 0o600))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want it to contain %q", err, c.want)
			}
		})
	}
}

func TestSecretPermissions(t *testing.T) {
	_, err := LoadConfig(writeAgentFiles(t, nil, 0o644))
	if err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("world-readable secret: err = %v", err)
	}
}

func TestSecretFromEnv(t *testing.T) {
	key, _ := protocol.NewKey()
	t.Setenv(SecretEnv, protocol.EncodeKey(key))
	cfg, err := LoadConfig(writeAgentFiles(t, func(m map[string]any) { m["secret_file"] = "" }, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	if string(cfg.secret) != string(key) {
		t.Error("secret from environment not used")
	}
	t.Setenv(SecretEnv, "")
	if _, err := LoadConfig(writeAgentFiles(t, func(m map[string]any) { m["secret_file"] = "" }, 0o600)); err == nil {
		t.Error("missing secret accepted")
	}
}

func TestServerURL(t *testing.T) {
	for url, ok := range map[string]bool{
		"http://127.0.0.1:8080":  true,
		"http://localhost:8080":  true,
		"http://[::1]:8080":      true,
		"https://netcrawl.lan":   true,
		"https://10.0.0.5:8443/": true,
		"http://10.0.0.5:8080":   false,
		"https://user:pw@x.lan":  false,
		"https://x.lan/?a=1":     false,
		"":                       false,
	} {
		if err := checkServerURL(url); (err == nil) != ok {
			t.Errorf("checkServerURL(%q) = %v, want ok=%v", url, err, ok)
		}
	}
}
