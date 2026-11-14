package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const minimal = `{"version": 1, "targets": {"include": ["192.168.1.0/24"]}, "ports": {"enabled": true, "preset": "tiny"}}`

func TestParseDefaults(t *testing.T) {
	cfg, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Performance.MaxConcurrentConnections != DefaultMaxConcurrentConnections ||
		cfg.Ports.TimeoutMs != DefaultPortTimeoutMs ||
		cfg.Hostname.TimeoutMs != DefaultHostnameTimeoutMs ||
		cfg.Enrichment.TimeoutMs != DefaultEnrichmentTimeoutMs ||
		cfg.Output.Directory != DefaultOutputDirectory {
		t.Errorf("defaults not applied: %+v", cfg)
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "configs", "example.json"))
	if err != nil {
		t.Fatalf("configs/example.json must stay valid: %v", err)
	}
	if _, err := cfg.PortList(); err != nil {
		t.Fatal(err)
	}
}

func TestPortList(t *testing.T) {
	cfg, err := Parse([]byte(`{"version": 1, "targets": {"include": ["10.0.0.1"]},
		"ports": {"enabled": true, "preset": "custom", "custom": [8080, "9000-9002"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := cfg.PortList()
	if err != nil {
		t.Fatal(err)
	}
	if want := []int{8080, 9000, 9001, 9002}; !reflect.DeepEqual(got, want) {
		t.Errorf("PortList = %v, want %v", got, want)
	}

	cfg.Ports.Enabled = false
	if got, _ := cfg.PortList(); len(got) != 0 {
		t.Errorf("PortList with ports disabled = %v, want empty", got)
	}
}

func TestPortsDisabledSkipsPortValidation(t *testing.T) {
	_, err := Parse([]byte(`{"version": 1, "targets": {"include": ["10.0.0.1"]}, "ports": {"enabled": false, "preset": "whatever"}}`))
	if err != nil {
		t.Errorf("ports.enabled=false must not validate the preset: %v", err)
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name, json, want string
	}{
		{"version", `{"version": 2, "targets": {"include": ["10.0.0.1"]}}`, "unsupported config version 2"},
		{"no targets", `{"version": 1, "targets": {"include": []}}`, "no targets configured"},
		{"bad target", `{"version": 1, "targets": {"include": ["10.0.0.300"]}}`, "targets.include"},
		{"bad deny", `{"version": 1, "targets": {"include": ["10.0.0.1"], "deny": ["x"]}}`, "targets.deny"},
		{"ipv6", `{"version": 1, "targets": {"include": ["::1"]}}`, "IPv6"},
		{"unknown preset", `{"version": 1, "targets": {"include": ["10.0.0.1"]}, "ports": {"enabled": true, "preset": "comon"}}`, "unknown port preset"},
		{"bad custom port", `{"version": 1, "targets": {"include": ["10.0.0.1"]}, "ports": {"enabled": true, "custom": [70000]}}`, "out of range"},
		{"no ports", `{"version": 1, "targets": {"include": ["10.0.0.1"]}, "ports": {"enabled": true, "preset": "custom"}}`, "no ports selected"},
		{"negative timeout", `{"version": 1, "targets": {"include": ["10.0.0.1"]}, "ports": {"timeoutMs": -5}}`, "ports.timeoutMs"},
		{"huge timeout", `{"version": 1, "targets": {"include": ["10.0.0.1"]}, "hostname": {"timeoutMs": 600000}}`, "hostname.timeoutMs"},
		{"negative concurrency", `{"version": 1, "targets": {"include": ["10.0.0.1"]}, "performance": {"maxConcurrentConnections": -1}}`, "maxConcurrentConnections"},
		{"unknown key", `{"version": 1, "targets": {"include": ["10.0.0.1"]}, "ports": {"timout": 400}}`, "unknown field"},
		{"trailing data", `{"version": 1, "targets": {"include": ["10.0.0.1"]}} {}`, "unexpected data"},
		{"bad json", `{"version": 1,`, "parse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.json))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestValidationReportsAllErrors(t *testing.T) {
	_, err := Parse([]byte(`{"version": 3, "targets": {"include": []}, "ports": {"enabled": true, "preset": "nope"}}`))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"version", "no targets", "unknown port preset"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q is missing %q", err, want)
		}
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.json"))
	if err == nil || !strings.Contains(err.Error(), "read config") {
		t.Errorf("error = %v", err)
	}
}

func TestLoadNamesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"version": 9}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("error should name the file: %v", err)
	}
}
