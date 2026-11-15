// Package agent implements netcrawl-agent: it polls netcrawl-server for
// jobs, checks every job against local limits before touching the
// network, scans and submits a signed result.
package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"netcrawler/internal/protocol"
	"netcrawler/internal/scope"
	"netcrawler/internal/tlspin"
)

// MinPollInterval is the lowest allowed polling interval.
const MinPollInterval = 60

// SecretEnv can hold the crawler secret instead of secret_file.
const SecretEnv = "NETCRAWL_AGENT_SECRET"

// Config is the local agent configuration (agent.json).
type Config struct {
	Version   int    `json:"version"`
	CrawlerID string `json:"crawler_id"`
	ServerURL string `json:"server_url"`
	// SecretFile holds the base64url crawler secret (mode 0600 or
	// stricter). If empty, NETCRAWL_AGENT_SECRET is used.
	SecretFile string  `json:"secret_file"`
	Polling    Polling `json:"polling"`
	Limits     Limits  `json:"limits"`
	// LockFile prevents two crawls from running at the same time.
	LockFile string `json:"lock_file"`
	// CAFile optionally adds a CA certificate for an https server_url.
	CAFile string `json:"ca_file"`
	// TLSPin trusts exactly this server key (sha256//<base64>, as curl's
	// --pinnedpubkey) instead of a CA, for servers with a self-signed
	// certificate. Set by "netcrawl-agent enroll".
	TLSPin string `json:"tls_pin,omitempty"`
	// ReverseDNS allows PTR lookups for found hosts when a job asks for
	// them. Lookups contact the configured DNS resolver.
	ReverseDNS bool `json:"reverse_dns"`

	secret  []byte
	baseDir string
}

type Polling struct {
	IntervalSeconds int `json:"interval_seconds"`
}

// Limits are the local scan boundaries: the release of what this crawler
// may scan. A job outside of them is rejected before any connection is
// made, whatever the server says. Only private ranges are accepted unless
// AllowPublicRanges is set.
type Limits struct {
	Allow             []string `json:"allow"`
	MaxHosts          int      `json:"max_hosts"`
	AllowPublicRanges bool     `json:"allow_public_ranges"`
}

// LoadConfig reads and validates the agent config and loads the secret.
// It makes no network connections.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read agent config: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("agent config %s: parse: %w", path, err)
	}
	cfg.baseDir = filepath.Dir(path)
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("agent config %s: %w", path, err)
	}
	if err := cfg.loadSecret(); err != nil {
		return nil, fmt.Errorf("agent config %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) resolve(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.baseDir, p)
}

func (c *Config) validate() error {
	var errs []error
	add := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	if c.Version != 1 {
		add("unsupported version %d (expected 1)", c.Version)
	}
	if !protocol.ValidCrawlerID(c.CrawlerID) {
		add("crawler_id %q is missing or invalid", c.CrawlerID)
	}
	if err := checkServerURL(c.ServerURL); err != nil {
		add("server_url: %v", err)
	}
	if c.Polling.IntervalSeconds < MinPollInterval {
		add("polling.interval_seconds must be at least %d, got %d", MinPollInterval, c.Polling.IntervalSeconds)
	}
	if err := scope.CheckRelease(c.Limits.Allow, c.Limits.MaxHosts, c.Limits.AllowPublicRanges); err != nil {
		add("limits: %v", err)
	}
	if c.TLSPin != "" && !tlspin.Valid(c.TLSPin) {
		add("tls_pin %q is invalid (expected sha256//<base64>)", c.TLSPin)
	}
	if c.TLSPin != "" && c.CAFile != "" {
		add("set either tls_pin or ca_file, not both")
	}
	if strings.TrimSpace(c.LockFile) == "" {
		add("lock_file is required")
	}
	return errors.Join(errs...)
}

// checkServerURL allows https everywhere and plain http only for loopback
// servers, because job polls hand out result tokens.
func checkServerURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("invalid URL %q", raw)
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("must be a plain scheme://host[:port] URL, got %q", raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("plain http is only allowed for a loopback server, use https for %q", host)
	default:
		return fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
}

func (c *Config) loadSecret() error {
	var raw string
	if c.SecretFile != "" {
		path := c.resolve(c.SecretFile)
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("secret_file: %w", err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("secret_file %s is accessible by group/others (mode %04o), run: chmod 600 %s", path, info.Mode().Perm(), path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("secret_file: %w", err)
		}
		raw = string(data)
	} else {
		raw = os.Getenv(SecretEnv)
		if raw == "" {
			return fmt.Errorf("no secret: set secret_file or %s", SecretEnv)
		}
	}
	secret, err := protocol.DecodeKey(raw)
	if err != nil {
		return fmt.Errorf("crawler secret: %w", err)
	}
	c.secret = secret
	return nil
}
