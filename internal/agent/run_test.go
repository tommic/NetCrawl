package agent

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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
