package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunStopsWhenRejected(t *testing.T) {
	var polls, status atomic.Int32
	status.Store(http.StatusUnauthorized)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		polls.Add(1)
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()

	run := func() (error, int32) {
		polls.Store(0)
		path := writeAgentFiles(t, func(m map[string]any) { m["server_url"] = srv.URL }, 0o600)
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		a, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		a.interval = time.Millisecond
		a.Logf = func(string, ...any) {}
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		return a.Run(ctx), polls.Load()
	}

	err, n := run()
	if !errors.Is(err, ErrCredentialsRejected) || n != MaxRejectedPolls {
		t.Fatalf("401: err=%v after %d polls", err, n)
	}
	if !strings.Contains(err.Error(), "reinstalled") {
		t.Errorf("message: %v", err)
	}

	// Other errors (server down, 500) keep the agent running.
	status.Store(http.StatusInternalServerError)
	err, n = run()
	if !errors.Is(err, context.DeadlineExceeded) || n <= MaxRejectedPolls {
		t.Fatalf("500: err=%v after %d polls", err, n)
	}
}

// A server with another version makes the agent ask its updater (trigger
// file next to the lock file), at most once per hour; auto_update false
// turns that off.
func TestUpdateRequested(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-NetCrawl-Version", "99.0.0")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	start := func(mod func(map[string]any)) (*Agent, string) {
		path := writeAgentFiles(t, func(m map[string]any) { m["server_url"] = srv.URL; mod(m) }, 0o600)
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		a, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { a.Close() })
		a.Logf = func(string, ...any) {}
		return a, filepath.Join(filepath.Dir(cfg.resolve(cfg.LockFile)), UpdateTriggerName)
	}

	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	a, trigger := start(func(map[string]any) {})
	a.Now = func() time.Time { return now }
	if _, err := a.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(trigger); err != nil || string(b) != "99.0.0\n" {
		t.Fatalf("trigger: %q %v", b, err)
	}
	// Removed by the updater; not asked again within the hour.
	_ = os.Remove(trigger)
	now = now.Add(30 * time.Minute)
	_, _ = a.RunOnce(context.Background())
	if _, err := os.Stat(trigger); err == nil {
		t.Error("asked again within the hour")
	}
	now = now.Add(31 * time.Minute)
	_, _ = a.RunOnce(context.Background())
	if _, err := os.Stat(trigger); err != nil {
		t.Error("not asked again after an hour")
	}

	b, trigger2 := start(func(m map[string]any) { m["auto_update"] = false })
	_, _ = b.RunOnce(context.Background())
	if _, err := os.Stat(trigger2); err == nil {
		t.Error("auto_update false still asked for an update")
	}
}
