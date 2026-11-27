package server

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"netcrawler/internal/store/memstore"
	"netcrawler/internal/version"
)

// The updater script (agent-update.sh) against a real server: it installs
// the offered agent only if checksum and version match, and leaves an
// up-to-date or opted-out crawler alone.
func TestAgentUpdateScript(t *testing.T) {
	for _, tool := range []string{"sh", "curl", "sha256sum", "install"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	arch := map[string]string{"amd64": "amd64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" {
		t.Skip("unsupported architecture")
	}

	agentDir := t.TempDir()
	offered := filepath.Join(agentDir, "netcrawl-agent-linux-"+arch)
	writeFakeAgent(t, offered, version.Version)
	ic := &InstallConfig{AgentDir: agentDir}
	s := New(memstore.New(), Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Install: ic})
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	root := t.TempDir()
	for _, d := range []string{"etc/netcrawl-agent", "usr/local/bin", "var/lib/netcrawl-agent"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	installed := filepath.Join(root, "usr/local/bin/netcrawl-agent")
	trigger := filepath.Join(root, "var/lib/netcrawl-agent/update-requested")
	agentConf := filepath.Join(root, "etc/netcrawl-agent/agent.json")
	restarts := filepath.Join(root, "restarts")
	writeFile(t, filepath.Join(root, "etc/netcrawl-agent/update.conf"), "SERVER_URL="+srv.URL+"\nTLS_PIN=\n", 0o644)
	writeFile(t, agentConf, `{"crawler_id": "lab-1"}`, 0o644)
	systemctl := filepath.Join(root, "systemctl")
	writeFile(t, systemctl, "#!/bin/sh\necho \"$*\" >> "+restarts+"\n", 0o755)

	run := func() (string, error) {
		t.Helper()
		cmd := exec.Command("sh", "-c", agentUpdateScript)
		cmd.Env = append(os.Environ(), "NETCRAWL_UPDATE_ROOT="+root, "SYSTEMCTL="+systemctl)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	restarted := func() string { b, _ := os.ReadFile(restarts); return string(b) }

	// Old agent: replaced, crawler restarted, trigger consumed.
	writeFakeAgent(t, installed, "0.1.0")
	writeFile(t, trigger, "anything\n", 0o644)
	if out, err := run(); err != nil || !strings.Contains(out, "updated to "+version.Version) {
		t.Fatalf("update: %v\n%s", err, out)
	}
	if v := agentVersion(t, installed); v != version.Version {
		t.Fatalf("installed version %q", v)
	}
	if restarted() != "restart netcrawl-agent\n" {
		t.Errorf("restarts = %q", restarted())
	}
	if _, err := os.Stat(trigger); err == nil {
		t.Error("trigger not removed")
	}

	// Up to date: nothing happens.
	if out, err := run(); err != nil || !strings.Contains(out, "up to date") || restarted() != "restart netcrawl-agent\n" {
		t.Fatalf("up to date: %v %q\n%s", err, restarted(), out)
	}

	// The download doesn't match the manifest's checksum: kept.
	writeFakeAgent(t, installed, "0.1.0")
	info, _ := os.Stat(offered)
	sumBefore := s.agents.sum(arch)
	writeFakeAgent(t, offered, version.Version+"-tampered")
	_ = os.Chtimes(offered, info.ModTime(), info.ModTime()) // the server keeps its cached checksum
	if s.agents.sum(arch) != sumBefore {
		t.Fatal("test setup: checksum cache not kept")
	}
	if out, err := run(); err == nil || !strings.Contains(out, "checksum mismatch") || agentVersion(t, installed) != "0.1.0" {
		t.Fatalf("tampered binary: %v\n%s", err, out)
	}

	// The binary reports another version than the manifest: kept.
	writeFakeAgent(t, offered, "9.9.9")
	_ = os.Chtimes(offered, time.Now(), time.Now().Add(time.Second))
	if out, err := run(); err == nil || !strings.Contains(out, "reports version '9.9.9'") || agentVersion(t, installed) != "0.1.0" {
		t.Fatalf("wrong version: %v\n%s", err, out)
	}

	// auto_update false: the updater does nothing.
	writeFakeAgent(t, offered, version.Version)
	_ = os.Chtimes(offered, time.Now(), time.Now().Add(2*time.Second))
	writeFile(t, agentConf, `{"crawler_id": "lab-1", "auto_update": false}`, 0o644)
	if out, err := run(); err != nil || !strings.Contains(out, "auto_update is off") || agentVersion(t, installed) != "0.1.0" {
		t.Fatalf("auto_update false: %v\n%s", err, out)
	}
}

func writeFakeAgent(t *testing.T, path, v string) {
	t.Helper()
	writeFile(t, path, "#!/bin/sh\n[ \"$1\" = --version ] && echo '"+v+"'\n", 0o755)
}

func agentVersion(t *testing.T, path string) string {
	t.Helper()
	out, err := exec.Command(path, "--version").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(path, mode)
}
