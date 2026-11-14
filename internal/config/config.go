// Package config loads and validates the scan configuration (config.json).
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"netcrawler/internal/iprange"
	"netcrawler/internal/ports"
)

type Config struct {
	Version     int         `json:"version"`
	Targets     Targets     `json:"targets"`
	Ports       Ports       `json:"ports"`
	Hostname    Hostname    `json:"hostname"`
	Enrichment  Enrichment  `json:"enrichment"`
	Performance Performance `json:"performance"`
	Output      Output      `json:"output"`
}

type Targets struct {
	Include []string `json:"include"`
	Deny    []string `json:"deny"`
}

// Ports selects which TCP ports are probed. Custom entries are single ports
// (8080 or "8080") or inclusive ranges ("9000-9010").
type Ports struct {
	Enabled   bool         `json:"enabled"`
	Preset    string       `json:"preset"`
	Custom    []ports.Spec `json:"custom"`
	TimeoutMs int          `json:"timeoutMs"`
}

type Hostname struct {
	Enabled    bool `json:"enabled"`
	ReverseDNS bool `json:"reverseDns"`
	TimeoutMs  int  `json:"timeoutMs"`
}

// Enrichment controls optional service detail probing (TLS certificate,
// HTTP title/Server header, plain-text protocol banners) for open ports
// that support it. Disabled by default: it opens extra connections per
// open port on top of the port scan itself.
type Enrichment struct {
	Enabled   bool `json:"enabled"`
	TimeoutMs int  `json:"timeoutMs"`
}

type Performance struct {
	MaxConcurrentConnections int `json:"maxConcurrentConnections"`
}

type Output struct {
	Directory   string `json:"directory"`
	PrettyPrint bool   `json:"prettyPrint"`
}

// Defaults applied when a value is omitted (zero).
const (
	DefaultMaxConcurrentConnections = 200
	DefaultPortTimeoutMs            = 500
	DefaultHostnameTimeoutMs        = 1000
	DefaultEnrichmentTimeoutMs      = 1000
	DefaultOutputDirectory          = "./results"

	// MaxConcurrentConnectionsLimit guards against configs that would
	// exhaust file descriptors or flood the network.
	MaxConcurrentConnectionsLimit = 10000
	// MaxTimeoutMs caps every timeout at one minute.
	MaxTimeoutMs = 60000
)

// Load reads, decodes, applies defaults to and validates a config file.
// Unknown keys are rejected so typos like "timout" are caught instead of
// being silently ignored.
func Load(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", filename, err)
	}
	return cfg, nil
}

// Parse decodes and validates config JSON.
func Parse(data []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if dec.More() {
		return nil, errors.New("parse: unexpected data after the JSON object")
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Performance.MaxConcurrentConnections == 0 {
		c.Performance.MaxConcurrentConnections = DefaultMaxConcurrentConnections
	}
	if c.Ports.TimeoutMs == 0 {
		c.Ports.TimeoutMs = DefaultPortTimeoutMs
	}
	if c.Hostname.TimeoutMs == 0 {
		c.Hostname.TimeoutMs = DefaultHostnameTimeoutMs
	}
	if c.Enrichment.TimeoutMs == 0 {
		c.Enrichment.TimeoutMs = DefaultEnrichmentTimeoutMs
	}
	if strings.TrimSpace(c.Output.Directory) == "" {
		c.Output.Directory = DefaultOutputDirectory
	}
}

// Validate reports every problem in the config at once, so a user can fix
// them in one go.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.Version != 1 {
		add("unsupported config version %d (expected 1)", c.Version)
	}
	if len(c.Targets.Include) == 0 {
		add("targets.include: no targets configured")
	}
	for _, t := range c.Targets.Include {
		if _, err := iprange.Parse(t); err != nil {
			add("targets.include: %v", err)
		}
	}
	for _, t := range c.Targets.Deny {
		if _, err := iprange.Parse(t); err != nil {
			add("targets.deny: %v", err)
		}
	}

	if c.Ports.Enabled {
		list, err := ports.Resolve(c.Ports.Preset, c.Ports.Custom)
		switch {
		case err != nil:
			add("ports: %v", err)
		case len(list) == 0:
			add("ports: enabled but no ports selected (set ports.preset or ports.custom)")
		}
	}

	checkTimeout := func(name string, v int) {
		if v < 0 || v > MaxTimeoutMs {
			add("%s: must be between 1 and %d ms, got %d", name, MaxTimeoutMs, v)
		}
	}
	checkTimeout("ports.timeoutMs", c.Ports.TimeoutMs)
	checkTimeout("hostname.timeoutMs", c.Hostname.TimeoutMs)
	checkTimeout("enrichment.timeoutMs", c.Enrichment.TimeoutMs)

	if n := c.Performance.MaxConcurrentConnections; n < 1 || n > MaxConcurrentConnectionsLimit {
		add("performance.maxConcurrentConnections: must be between 1 and %d, got %d", MaxConcurrentConnectionsLimit, n)
	}
	return errors.Join(errs...)
}

// PortList returns the resolved, sorted port list (empty if port scanning
// is disabled).
func (c *Config) PortList() ([]int, error) {
	if !c.Ports.Enabled {
		return nil, nil
	}
	return ports.Resolve(c.Ports.Preset, c.Ports.Custom)
}
