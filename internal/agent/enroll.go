package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"netcrawler/internal/protocol"
	"netcrawler/internal/scope"
	"netcrawler/internal/version"
)

// EnrollOptions configure Enroll.
type EnrollOptions struct {
	ServerURL string
	Token     string
	// TLSPin pins the server key (self-signed certificate). Empty: the
	// system CAs are used.
	TLSPin string
	// ConfigDir receives agent.json and agent.secret.
	ConfigDir string
	// StateDir receives the lock file; defaults to ConfigDir.
	StateDir string
	// Force overwrites an existing agent.json.
	Force bool
	// HTTP overrides the client (tests).
	HTTP *http.Client
}

// Enroll redeems a one-time code at the server and writes agent.json and
// agent.secret. The local limits are taken from the server's
// registration once, here, and are fixed afterwards: a server cannot
// widen them later. Only private ranges are accepted.
func Enroll(ctx context.Context, o EnrollOptions) (*Config, error) {
	if !protocol.ValidToken(o.Token) {
		return nil, errors.New("invalid enrollment code")
	}
	if o.StateDir == "" {
		o.StateDir = o.ConfigDir
	}
	cfgPath := filepath.Join(o.ConfigDir, "agent.json")
	secretPath := filepath.Join(o.ConfigDir, "agent.secret")
	if _, err := os.Stat(cfgPath); err == nil && !o.Force {
		return nil, fmt.Errorf("%s already exists (use --force to replace it)", cfgPath)
	}

	cfg := &Config{
		Version:    1,
		ServerURL:  strings.TrimRight(o.ServerURL, "/"),
		SecretFile: secretPath,
		Polling:    Polling{IntervalSeconds: MinPollInterval},
		LockFile:   filepath.Join(o.StateDir, "agent.lock"),
		TLSPin:     o.TLSPin,
	}
	// Check URL and pin before the code is sent anywhere.
	if err := checkServerURL(cfg.ServerURL); err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	client := o.HTTP
	if client == nil {
		var err error
		if client, err = newHTTPClient(cfg); err != nil {
			return nil, err
		}
	}

	body, _ := json.Marshal(protocol.EnrollRequest{Token: o.Token, AgentVersion: version.Version})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.ServerURL+protocol.PathEnroll, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, errors.New("enroll: code unknown, already used or expired – create a new install command in the web UI")
	case http.StatusForbidden:
		return nil, errors.New("enroll: crawler is disabled on the server")
	default:
		return nil, fmt.Errorf("enroll: server answered %s", resp.Status)
	}
	var er protocol.EnrollResponse
	if err := json.Unmarshal(data, &er); err != nil {
		return nil, fmt.Errorf("enroll: bad response: %w", err)
	}
	secret, err := protocol.DecodeKey(er.Secret)
	if err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}
	if !protocol.ValidCrawlerID(er.CrawlerID) {
		return nil, fmt.Errorf("enroll: invalid crawler id %q", er.CrawlerID)
	}
	// Never public ranges via enrollment, whatever the server says.
	if err := scope.CheckRelease(er.Allow, er.MaxHosts, false); err != nil {
		return nil, fmt.Errorf("enroll: release from server rejected: %w", err)
	}
	cfg.CrawlerID = er.CrawlerID
	cfg.Limits = Limits{Allow: er.Allow, MaxHosts: er.MaxHosts}
	cfg.ReverseDNS = er.ReverseDNS
	if er.IntervalSeconds >= MinPollInterval {
		cfg.Polling.IntervalSeconds = er.IntervalSeconds
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("enroll: %w", err)
	}

	if err := os.MkdirAll(o.ConfigDir, 0o750); err != nil {
		return nil, err
	}
	if err := writeFile(secretPath, []byte(protocol.EncodeKey(secret)+"\n"), 0o600); err != nil {
		return nil, err
	}
	out, _ := json.MarshalIndent(cfg, "", "  ")
	if err := writeFile(cfgPath, append(out, '\n'), 0o640); err != nil {
		return nil, err
	}
	cfg.secret = secret
	cfg.baseDir = o.ConfigDir
	return cfg, nil
}

// writeFile replaces path atomically with the given mode.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
