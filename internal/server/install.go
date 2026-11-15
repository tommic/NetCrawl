package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"netcrawler/internal/agent"
	"netcrawler/internal/protocol"
	"netcrawler/internal/store"
	"netcrawler/internal/tlspin"
)

//go:embed install.sh.tmpl
var installTemplateText string

//go:embed uninstall.sh
var uninstallScript []byte

var installTemplate = template.Must(template.New("install").Parse(installTemplateText))

// AgentArchs are the architectures the installer supports.
var AgentArchs = []string{"amd64", "arm64"}

// InstallConfig enables the crawler installer.
type InstallConfig struct {
	// PublicURL is how crawlers reach this server, e.g.
	// https://192.168.1.5:8443 or https://netcrawl.example.org.
	PublicURL string
	// TLSPin pins the server key for a self-signed certificate (empty:
	// the certificate must be trusted by the system CAs).
	TLSPin string
	// AgentDir holds netcrawl-agent-linux-amd64 / -arm64.
	AgentDir string
}

// Validate checks the public URL (https, or http for loopback only, as
// the agent requires) and the pin.
func (c InstallConfig) Validate() error {
	u, err := url.Parse(c.PublicURL)
	if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("public URL %q: must be scheme://host[:port]", c.PublicURL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip := net.ParseIP(u.Hostname())
		if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("public URL %q: crawlers require https (http only for loopback tests)", c.PublicURL)
		}
	default:
		return fmt.Errorf("public URL %q: unsupported scheme", c.PublicURL)
	}
	if strings.ContainsAny(c.PublicURL, "'\"\\$` ") {
		return fmt.Errorf("public URL %q contains invalid characters", c.PublicURL)
	}
	if c.TLSPin != "" && !tlspin.Valid(c.TLSPin) {
		return fmt.Errorf("invalid TLS pin %q", c.TLSPin)
	}
	if c.TLSPin != "" && u.Scheme != "https" {
		return errors.New("a TLS pin needs an https public URL")
	}
	return nil
}

func (c InstallConfig) baseURL() string { return strings.TrimRight(c.PublicURL, "/") }

// InstallCommand is the one-liner shown to the admin.
func (c InstallConfig) InstallCommand(token string) string {
	return "curl -fsSL " + c.curlPin() + "'" + c.scriptURL(token) + "' | sudo sh"
}

// DownloadCommand fetches the script for review before running it.
func (c InstallConfig) DownloadCommand(token string) string {
	return "curl -fsSL " + c.curlPin() + "-o netcrawl-install.sh '" + c.scriptURL(token) + "' && less netcrawl-install.sh && sudo sh netcrawl-install.sh"
}

func (c InstallConfig) curlPin() string {
	if c.TLSPin == "" {
		return ""
	}
	return "-k --pinnedpubkey '" + c.TLSPin + "' "
}

func (c InstallConfig) scriptURL(token string) string {
	return c.baseURL() + fmt.Sprintf(protocol.PathInstallScriptFmt, token)
}

// agentBinaries caches the checksums of the agent binaries.
type agentBinaries struct {
	dir  string
	mu   sync.Mutex
	sums map[string]string
	mods map[string]time.Time
}

func (a *agentBinaries) path(arch string) string {
	return filepath.Join(a.dir, "netcrawl-agent-linux-"+arch)
}

// sum returns the SHA-256 of the binary for arch, or "" if missing.
func (a *agentBinaries) sum(arch string) string {
	if a == nil || a.dir == "" {
		return ""
	}
	info, err := os.Stat(a.path(arch))
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.sums == nil {
		a.sums, a.mods = map[string]string{}, map[string]time.Time{}
	}
	if s, ok := a.sums[arch]; ok && a.mods[arch].Equal(info.ModTime()) {
		return s
	}
	f, err := os.Open(a.path(arch))
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	s := hex.EncodeToString(h.Sum(nil))
	a.sums[arch], a.mods[arch] = s, info.ModTime()
	return s
}

// EnrollmentView is returned when an install command is created.
type EnrollmentView struct {
	CrawlerID       string    `json:"crawler_id"`
	ExpiresAt       time.Time `json:"expires_at"`
	Command         string    `json:"command"`
	DownloadCommand string    `json:"download_command"`
	ServerURL       string    `json:"server_url"`
	TLSPin          string    `json:"tls_pin,omitempty"`
	Architectures   []string  `json:"architectures"`
}

// ErrInstallerDisabled is returned when no public URL is configured.
var ErrInstallerDisabled = errors.New("the installer is not configured: start the server with --public-url")

// CreateEnrollment creates a one-time install code for a crawler. An
// earlier unused code of the crawler becomes invalid. Redeeming the code
// replaces the crawler's secret.
func CreateEnrollment(ctx context.Context, st store.Store, ic *InstallConfig, actor, crawlerID string, reverseDNS bool, now time.Time) (EnrollmentView, error) {
	if ic == nil {
		return EnrollmentView{}, invalid("%v", ErrInstallerDisabled)
	}
	c, err := st.Crawler(ctx, crawlerID)
	if errors.Is(err, store.ErrNotFound) {
		return EnrollmentView{}, invalid("unknown crawler %q", crawlerID)
	}
	if err != nil {
		return EnrollmentView{}, err
	}
	if !c.Enabled {
		return EnrollmentView{}, invalid("crawler %q is disabled", crawlerID)
	}
	key, err := protocol.NewKey()
	if err != nil {
		return EnrollmentView{}, err
	}
	token := protocol.EncodeKey(key)
	e := store.Enrollment{TokenHash: hashToken(token), CrawlerID: crawlerID, ReverseDNS: reverseDNS, CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(protocol.EnrollTTL)}
	if err := st.CreateEnrollment(ctx, e); err != nil {
		return EnrollmentView{}, err
	}
	_ = st.Audit(ctx, actor, "crawler.enrollment.create", map[string]any{"id": crawlerID, "expires_at": e.ExpiresAt, "reverse_dns": reverseDNS})
	return EnrollmentView{
		CrawlerID: crawlerID, ExpiresAt: e.ExpiresAt,
		Command: ic.InstallCommand(token), DownloadCommand: ic.DownloadCommand(token),
		ServerURL: ic.baseURL(), TLSPin: ic.TLSPin, Architectures: AgentArchs,
	}, nil
}

func (s *Server) registerInstallRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /install/uninstall", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = w.Write(uninstallScript)
	})
	mux.HandleFunc("GET /install/agent/{file}", s.handleAgentBinary)
	mux.HandleFunc("GET /install/{token}", s.handleInstallScript)
	mux.HandleFunc("POST "+protocol.PathEnroll, s.handleEnroll)
	mux.Handle("POST /api/v1/admin/crawlers/{id}/enroll", s.admin(s.handleCreateEnrollment))
	mux.Handle("PUT /api/v1/admin/crawlers/{id}", s.admin(s.handleUpdateCrawler))
	mux.Handle("GET /api/v1/admin/settings/public-url", s.admin(s.handleGetPublicURL))
	mux.Handle("PUT /api/v1/admin/settings/public-url", s.admin(s.handleSetPublicURL))
}

func (s *Server) handleUpdateCrawler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled  *bool    `json:"enabled"`
		Allow    []string `json:"allow"`
		MaxHosts *int     `json:"max_hosts"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	id := r.PathValue("id")
	actor := adminFrom(r.Context()).Username
	if req.Enabled == nil && req.Allow == nil && req.MaxHosts == nil {
		writeError(w, http.StatusBadRequest, "nothing to change (expected \"enabled\" or \"allow\"/\"max_hosts\")")
		return
	}
	if req.Allow != nil || req.MaxHosts != nil {
		if req.Allow == nil || req.MaxHosts == nil {
			writeError(w, http.StatusBadRequest, "a release change needs both allow and max_hosts")
			return
		}
		if err := UpdateCrawlerRelease(r.Context(), s.st, actor, id, req.Allow, *req.MaxHosts, s.now()); err != nil {
			s.serviceError(w, err)
			return
		}
	}
	if req.Enabled != nil {
		if err := SetCrawlerEnabled(r.Context(), s.st, actor, id, *req.Enabled); err != nil {
			s.serviceError(w, err)
			return
		}
	}
	c, err := s.st.Crawler(r.Context(), id)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, crawlerView(c))
}

func (s *Server) handleCreateEnrollment(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ReverseDNS bool `json:"reverse_dns"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	v, err := CreateEnrollment(r.Context(), s.st, s.installConfig(r.Context()), adminFrom(r.Context()).Username, r.PathValue("id"), req.ReverseDNS, s.now())
	if err != nil {
		s.serviceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (s *Server) handleInstallScript(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	ic := s.installConfig(r.Context())
	if ic == nil || !protocol.ValidToken(token) {
		http.NotFound(w, r)
		return
	}
	e, err := s.st.Enrollment(r.Context(), hashToken(token), s.now())
	if errors.Is(err, store.ErrNotFound) {
		s.log.Warn("install script: unknown, used or expired code", "remote", clientIP(r))
		http.Error(w, "install code unknown, used or expired: create a new install command in the web UI\n", http.StatusNotFound)
		return
	}
	if err != nil {
		s.internalError(w, err)
		return
	}
	var buf bytes.Buffer
	err = installTemplate.Execute(&buf, map[string]string{
		"ServerURL": ic.baseURL(), "TLSPin": ic.TLSPin, "CrawlerID": e.CrawlerID, "Token": token,
		"SHA256AMD64": s.agents.sum("amd64"), "SHA256ARM64": s.agents.sum("arm64"),
	})
	if err != nil {
		s.internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) handleAgentBinary(w http.ResponseWriter, r *http.Request) {
	arch, ok := strings.CutPrefix(r.PathValue("file"), "linux-")
	if !ok || s.agents.sum(arch) == "" {
		http.NotFound(w, r)
		return
	}
	known := false
	for _, a := range AgentArchs {
		known = known || a == arch
	}
	if !known {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=netcrawl-agent")
	http.ServeFile(w, r, s.agents.path(arch))
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if s.installConfig(r.Context()) == nil {
		http.NotFound(w, r)
		return
	}
	var req protocol.EnrollRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !protocol.ValidToken(req.Token) {
		writeError(w, http.StatusNotFound, "unknown, used or expired code")
		return
	}
	secret, err := protocol.NewKey()
	if err != nil {
		s.internalError(w, err)
		return
	}
	c, e, err := s.st.RedeemEnrollment(r.Context(), hashToken(req.Token), secret, s.now())
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.log.Warn("enroll: unknown, used or expired code", "remote", clientIP(r))
		_ = s.st.Audit(r.Context(), "anonymous", "crawler.enroll.failed", map[string]any{"remote": clientIP(r)})
		writeError(w, http.StatusNotFound, "unknown, used or expired code")
		return
	case errors.Is(err, store.ErrForbidden):
		writeError(w, http.StatusForbidden, "crawler disabled")
		return
	case err != nil:
		s.internalError(w, err)
		return
	}
	_ = s.st.Audit(r.Context(), c.ID, "crawler.enroll", map[string]any{"remote": clientIP(r), "agent_version": req.AgentVersion})
	s.log.Info("crawler enrolled", "crawler", c.ID, "remote", clientIP(r))
	writeJSON(w, http.StatusOK, protocol.EnrollResponse{
		CrawlerID: c.ID, Secret: protocol.EncodeKey(secret), Allow: c.Allow, MaxHosts: c.MaxHosts,
		ReverseDNS: e.ReverseDNS, IntervalSeconds: agent.MinPollInterval,
	})
}

// SettingPublicURL is the server setting holding the public URL set in
// the web UI.
const SettingPublicURL = "public_url"

// installConfig returns the active installer configuration: the fixed one
// from the command line, else the public URL set in the web UI, else nil.
func (s *Server) installConfig(ctx context.Context) *InstallConfig {
	if s.install != nil {
		return s.install
	}
	u, err := s.st.Setting(ctx, SettingPublicURL)
	if err != nil || u == "" {
		return nil
	}
	ic := s.uiInstallConfig(u)
	if ic.Validate() != nil {
		return nil
	}
	return &ic
}

// uiInstallConfig builds the installer configuration for a URL set in the
// web UI: the server's own certificate pin applies to https only.
func (s *Server) uiInstallConfig(u string) InstallConfig {
	ic := s.installDefaults
	ic.PublicURL = u
	if !strings.HasPrefix(u, "https://") {
		ic.TLSPin = ""
	}
	return ic
}

// PublicURLView describes the public URL setting.
type PublicURLView struct {
	PublicURL string `json:"public_url"`
	// Source is "env" (NETCRAWL_PUBLIC_URL, not editable), "ui" or "".
	Source string `json:"source"`
	TLSPin string `json:"tls_pin,omitempty"`
}

func (s *Server) publicURLView(ctx context.Context) PublicURLView {
	if s.install != nil {
		return PublicURLView{PublicURL: s.install.PublicURL, Source: "env", TLSPin: s.install.TLSPin}
	}
	if ic := s.installConfig(ctx); ic != nil {
		return PublicURLView{PublicURL: ic.PublicURL, Source: "ui", TLSPin: ic.TLSPin}
	}
	return PublicURLView{}
}

func (s *Server) handleGetPublicURL(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.publicURLView(r.Context()))
}

func (s *Server) handleSetPublicURL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicURL string `json:"public_url"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if s.install != nil {
		writeError(w, http.StatusConflict, "the public URL is set by NETCRAWL_PUBLIC_URL / --public-url on the server")
		return
	}
	u := strings.TrimRight(strings.TrimSpace(req.PublicURL), "/")
	ic := s.uiInstallConfig(u)
	if err := ic.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.st.SetSetting(r.Context(), SettingPublicURL, u, s.now()); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.st.Audit(r.Context(), adminFrom(r.Context()).Username, "settings.public_url", map[string]any{"public_url": u})
	writeJSON(w, http.StatusOK, s.publicURLView(r.Context()))
}
