package eventlog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteAndRetention(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "events-2026-01-01.jsonl")
	keep := filepath.Join(dir, "events-2026-08-01.jsonl")
	other := filepath.Join(dir, "notes.txt")
	for _, f := range []string{old, keep, other} {
		if err := os.WriteFile(f, []byte("x\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	w, err := New(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 1, 23, 59, 0, 0, time.UTC)
	err = w.Write([]Entry{
		{At: at, Network: "Heimnetz", NetworkID: 1, IP: "10.0.0.5", Type: "port.opened", Severity: "warning", Message: "Port 22", Details: json.RawMessage(`{"port":22}`)},
		{At: at.Add(2 * time.Minute), Network: "Heimnetz", NetworkID: 1, Type: "host.new", Severity: "info", Message: "neu"},
	})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "events-2026-09-01.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var lines []Entry
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("invalid JSON line %q: %v", sc.Text(), err)
		}
		lines = append(lines, e)
	}
	if len(lines) != 1 || lines[0].IP != "10.0.0.5" || string(lines[0].Details) != `{"port":22}` {
		t.Errorf("day file = %+v", lines)
	}
	if _, err := os.Stat(filepath.Join(dir, "events-2026-09-02.jsonl")); err != nil {
		t.Error("entry after midnight must go to the next day's file")
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("file older than 180 days not deleted")
	}
	for _, f := range []string{keep, other} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s must be kept: %v", f, err)
		}
	}
	var nilWriter *Writer
	if err := nilWriter.Write([]Entry{{}}); err != nil {
		t.Error("nil writer must discard")
	}
}
