// Package eventlog appends inventory events as JSON lines to one file per
// day (events-YYYY-MM-DD.jsonl) and deletes files older than the retention.
package eventlog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultRetention keeps event files for 180 days.
const DefaultRetention = 180 * 24 * time.Hour

// Entry is one line of the log.
type Entry struct {
	At        time.Time       `json:"at"`
	Network   string          `json:"network"`
	NetworkID int64           `json:"network_id"`
	IP        string          `json:"ip,omitempty"`
	Type      string          `json:"type"`
	Severity  string          `json:"severity"`
	Message   string          `json:"message"`
	Details   json.RawMessage `json:"details,omitempty"`
	JobID     string          `json:"job_id,omitempty"`
	Baseline  bool            `json:"baseline,omitempty"`
}

// Writer appends entries. A nil *Writer discards everything.
type Writer struct {
	dir       string
	retention time.Duration
	mu        sync.Mutex
	lastClean string
}

// New creates the directory if needed.
func New(dir string, retention time.Duration) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("event log: %w", err)
	}
	if retention <= 0 {
		retention = DefaultRetention
	}
	return &Writer{dir: dir, retention: retention}, nil
}

const prefix, suffix = "events-", ".jsonl"

// Write appends the entries to the file of their day (UTC).
func (w *Writer) Write(entries []Entry) error {
	if w == nil || len(entries) == 0 {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	byDay := map[string][]Entry{}
	for _, e := range entries {
		day := e.At.UTC().Format("2006-01-02")
		byDay[day] = append(byDay[day], e)
	}
	for day, list := range byDay {
		f, err := os.OpenFile(filepath.Join(w.dir, prefix+day+suffix), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return fmt.Errorf("event log: %w", err)
		}
		enc := json.NewEncoder(f)
		for _, e := range list {
			if err := enc.Encode(e); err != nil {
				f.Close()
				return fmt.Errorf("event log: %w", err)
			}
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("event log: %w", err)
		}
		if day != w.lastClean {
			w.lastClean = day
			w.cleanup(entries[0].At)
		}
	}
	return nil
}

// cleanup deletes day files older than the retention.
func (w *Writer) cleanup(now time.Time) {
	names, _ := filepath.Glob(filepath.Join(w.dir, prefix+"*"+suffix))
	sort.Strings(names)
	cutoff := now.Add(-w.retention).UTC().Format("2006-01-02")
	for _, name := range names {
		day := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(name), prefix), suffix)
		if _, err := time.Parse("2006-01-02", day); err == nil && day < cutoff {
			_ = os.Remove(name)
		}
	}
}
