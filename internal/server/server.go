// Package server implements the HTTP API of netcrawl-server: the signed
// crawler API (job polling and result submission) and the admin API.
package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"netcrawler/internal/eventlog"
	"netcrawler/internal/inventory"
	"netcrawler/internal/notify"
	"netcrawler/internal/protocol"
	"netcrawler/internal/store"
	"netcrawler/internal/version"
)

// Request size limits.
const (
	MaxResultBodyBytes = 10 << 20
	maxSmallBodyBytes  = 64 << 10
)

// Options configures a Server.
type Options struct {
	// Now returns the current time (defaults to time.Now).
	Now func() time.Time
	// Logger receives request and security logs (defaults to slog.Default).
	Logger *slog.Logger
	// SecureCookies sets the Secure flag on the session cookie. Enable it
	// whenever the server is reached via HTTPS (directly or via a proxy).
	SecureCookies bool
	// SessionTTL is the admin session lifetime (default 12h).
	SessionTTL time.Duration
	// Embeddable allows the UI to be shown inside a frame on another site
	// (e.g. a development preview pane): it drops the frame restrictions
	// and sends the session cookie with SameSite=None; Secure. Only for
	// test environments behind HTTPS.
	Embeddable bool
	// EventLog receives inventory events as JSON lines (optional).
	EventLog *eventlog.Writer
	// Install enables the crawler installer with a fixed public URL
	// (NETCRAWL_PUBLIC_URL). Without it, the admin can set the URL in the
	// web UI; InstallDefaults then supply the pin and agent directory.
	Install         *InstallConfig
	InstallDefaults InstallConfig
	// NotifyHTTP overrides the HTTP client for webhook calls (tests).
	NotifyHTTP *http.Client
}

// Server serves the netcrawl API.
type Server struct {
	st              store.Store
	now             func() time.Time
	log             *slog.Logger
	secure          bool
	embed           bool
	sessTTL         time.Duration
	limiter         *loginLimiter
	events          *eventlog.Writer
	install         *InstallConfig
	installDefaults InstallConfig
	agents          *agentBinaries
	notifier        *notifier
}

// New returns a server backed by st.
func New(st store.Store, opts Options) *Server {
	s := &Server{st: st, now: opts.Now, log: opts.Logger, secure: opts.SecureCookies || opts.Embeddable, embed: opts.Embeddable, sessTTL: opts.SessionTTL}
	if s.now == nil {
		s.now = time.Now
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.sessTTL == 0 {
		s.sessTTL = 12 * time.Hour
	}
	s.limiter = newLoginLimiter(s.now)
	s.events = opts.EventLog
	s.install = opts.Install
	s.installDefaults = opts.InstallDefaults
	s.notifier = &notifier{sender: notify.Sender{HTTP: opts.NotifyHTTP}}
	agentDir := opts.InstallDefaults.AgentDir
	if opts.Install != nil {
		agentDir = opts.Install.AgentDir
	}
	s.agents = &agentBinaries{dir: agentDir}
	return s
}

// Handler returns the HTTP handler with all routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("GET "+protocol.PathJob, s.handleJobPoll)
	mux.HandleFunc("POST /api/v1/crawler/jobs/{id}/result", s.handleResult)

	mux.HandleFunc("POST /api/v1/admin/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/admin/logout", s.handleLogout)
	mux.Handle("GET /api/v1/admin/me", s.admin(s.handleMe))
	mux.Handle("GET /api/v1/admin/crawlers", s.admin(s.handleListCrawlers))
	mux.Handle("POST /api/v1/admin/crawlers", s.admin(s.handleCreateCrawler))
	mux.Handle("GET /api/v1/admin/jobs", s.admin(s.handleListJobs))
	mux.Handle("POST /api/v1/admin/jobs", s.admin(s.handleCreateJob))
	mux.Handle("GET /api/v1/admin/jobs/{id}", s.admin(s.handleGetJob))
	mux.Handle("GET /api/v1/admin/audit", s.admin(s.handleAudit))

	s.registerInventoryRoutes(mux)
	s.registerInstallRoutes(mux)
	s.registerNotifyRoutes(mux)
	s.registerUI(mux)
	return s.securityHeaders(mux)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	csp := contentSecurityPolicy + "; frame-ancestors 'none'"
	if s.embed {
		csp = contentSecurityPolicy
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", csp)
		if !s.embed {
			h.Set("X-Frame-Options", "DENY")
		}
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// sameSite is Strict normally and None for embeddable test setups.
func (s *Server) sameSite() http.SameSite {
	if s.embed {
		return http.SameSiteNoneMode
	}
	return http.SameSiteStrictMode
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, protocol.Error{Error: msg})
}

// readBody reads at most limit bytes; ok is false (and a response written)
// if the body is larger.
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			writeError(w, http.StatusBadRequest, "cannot read request body")
		}
		return nil, false
	}
	return body, true
}

// ---- Crawler API ----

// handleJobPoll hands out the next job. The request must be signed with
// the crawler secret.
func (s *Server) handleJobPoll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := s.now()
	body, ok := readBody(w, r, maxSmallBodyBytes)
	if !ok {
		return
	}
	crawlerID := r.Header.Get(protocol.HeaderCrawlerID)
	nonce := r.Header.Get(protocol.HeaderRequestNonce)
	reject := func(status int, reason string) {
		s.log.Warn("job poll rejected", "crawler", crawlerID, "status", status, "reason", reason, "remote", r.RemoteAddr)
		_ = s.st.Audit(ctx, "crawler:"+crawlerID, "job.poll.rejected", map[string]any{"status": status, "reason": reason, "remote": r.RemoteAddr})
		writeError(w, status, http.StatusText(status))
	}
	if !protocol.ValidCrawlerID(crawlerID) || !protocol.ValidNonce(nonce) {
		reject(http.StatusUnauthorized, "missing or malformed auth headers")
		return
	}
	ts, err := protocol.ParseTimestamp(r.Header.Get(protocol.HeaderRequestTimestamp), now)
	if err != nil {
		reject(http.StatusUnauthorized, err.Error())
		return
	}
	c, err := s.st.Crawler(ctx, crawlerID)
	if err != nil || !c.Enabled {
		reject(http.StatusUnauthorized, "unknown or disabled crawler")
		return
	}
	signing := protocol.SigningString(r.Method, r.URL.Path, crawlerID, "", ts, nonce, body)
	if !protocol.Verify(c.Secret, signing, r.Header.Get(protocol.HeaderRequestHMAC)) {
		reject(http.StatusUnauthorized, "invalid signature")
		return
	}
	if err := s.st.UseNonce(ctx, crawlerID, nonce, now); err != nil {
		if errors.Is(err, store.ErrReplay) {
			reject(http.StatusConflict, "nonce reused")
			return
		}
		s.internalError(w, err)
		return
	}
	_ = s.st.TouchCrawler(ctx, crawlerID, now, protocol.AgentVersionFromUserAgent(r.UserAgent()))
	w.Header().Set(protocol.HeaderServerVersion, version.Version)
	_ = s.st.PurgeNonces(ctx, now.Add(-2*protocol.MaxClockSkew))

	j, found, err := s.st.NextJob(ctx, crawlerID, now)
	if err != nil {
		s.internalError(w, err)
		return
	}
	if !found {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_ = s.st.Audit(ctx, "crawler:"+crawlerID, "job.delivered", map[string]any{"job_id": j.ID})
	s.log.Info("job delivered", "crawler", crawlerID, "job", j.ID)
	writeJSON(w, http.StatusOK, protocol.Job{
		JobID:       j.ID,
		CrawlerID:   j.CrawlerID,
		CreatedAt:   j.CreatedAt.UTC(),
		ExpiresAt:   j.ExpiresAt.UTC(),
		Targets:     j.Targets,
		MaxHosts:    j.MaxHosts,
		Ports:       j.Ports,
		TimeoutMs:   j.TimeoutMs,
		Kind:        j.Kind,
		Deny:        j.Deny,
		ReverseDNS:  j.ReverseDNS,
		Services:    j.Services,
		ResultToken: protocol.EncodeKey(j.ResultToken),
	})
}

// handleResult accepts a job result signed with the job's result token.
// Binding, expiry, signature and single use are checked atomically by the
// store.
func (s *Server) handleResult(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := s.now()
	jobID := r.PathValue("id")
	crawlerID := r.Header.Get(protocol.HeaderCrawlerID)
	nonce := r.Header.Get(protocol.HeaderResultNonce)
	signature := r.Header.Get(protocol.HeaderResultHMAC)

	reject := func(status int, reason string) {
		s.log.Warn("result rejected", "crawler", crawlerID, "job", jobID, "status", status, "reason", reason, "remote", r.RemoteAddr)
		_ = s.st.Audit(ctx, "crawler:"+crawlerID, "result.rejected", map[string]any{"job_id": jobID, "status": status, "reason": reason, "remote": r.RemoteAddr})
		msg := http.StatusText(status)
		if status == http.StatusConflict {
			msg = "replay"
		}
		writeError(w, status, msg)
	}

	body, ok := readBody(w, r, MaxResultBodyBytes)
	if !ok {
		return
	}
	if !protocol.ValidCrawlerID(crawlerID) || !protocol.ValidNonce(nonce) || signature == "" {
		reject(http.StatusUnauthorized, "missing or malformed auth headers")
		return
	}
	ts, err := protocol.ParseTimestamp(r.Header.Get(protocol.HeaderResultTimestamp), now)
	if err != nil {
		reject(http.StatusUnauthorized, err.Error())
		return
	}
	if c, err := s.st.Crawler(ctx, crawlerID); err != nil || !c.Enabled {
		reject(http.StatusUnauthorized, "unknown or disabled crawler")
		return
	}
	signing := protocol.SigningString(r.Method, r.URL.Path, crawlerID, jobID, ts, nonce, body)
	verify := func(token []byte) bool { return protocol.Verify(token, signing, signature) }

	// Authenticate before looking at the body, so a tampered body is
	// reported as an authentication failure, not as a format error.
	j, err := s.st.Job(ctx, jobID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		reject(http.StatusUnauthorized, "unknown job")
		return
	case err != nil:
		s.internalError(w, err)
		return
	case j.CrawlerID != crawlerID:
		reject(http.StatusForbidden, "job belongs to another crawler")
		return
	case !verify(j.ResultToken):
		reject(http.StatusUnauthorized, "invalid signature")
		return
	}

	var res protocol.Result
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&res); err != nil {
		reject(http.StatusBadRequest, "malformed result: "+err.Error())
		return
	}
	if res.JobID != jobID || res.CrawlerID != crawlerID {
		reject(http.StatusBadRequest, "result job_id/crawler_id do not match the request")
		return
	}

	sum := sha256.Sum256(body)
	err = s.st.SubmitResult(ctx, store.Submission{
		CrawlerID: crawlerID, JobID: jobID, Nonce: nonce, Now: now,
		Verify: verify, Body: body, BodySHA256: sum[:],
	})
	switch {
	case err == nil:
	case errors.Is(err, store.ErrUnauthorized):
		reject(http.StatusUnauthorized, "invalid signature")
		return
	case errors.Is(err, store.ErrForbidden):
		reject(http.StatusForbidden, "job not delivered to this crawler")
		return
	case errors.Is(err, store.ErrReplay):
		reject(http.StatusConflict, "result already submitted or nonce reused")
		return
	case errors.Is(err, store.ErrExpired):
		reject(http.StatusGone, "job expired")
		return
	default:
		s.internalError(w, err)
		return
	}
	_ = s.st.Audit(ctx, "crawler:"+crawlerID, "result.accepted", map[string]any{"job_id": jobID, "networks": len(res.Networks)})
	s.log.Info("result accepted", "crawler", crawlerID, "job", jobID)
	if j.NetworkID != nil {
		// The result is stored; an inventory error must not turn the
		// accepted submission into a failure for the crawler.
		events, err := s.applyInventory(ctx, *j.NetworkID, inventory.ApplyResult(j.Kind, j.ID, res, now))
		if err != nil {
			s.log.Error("inventory update failed", "network", *j.NetworkID, "job", jobID, "err", err)
			_ = s.st.Audit(ctx, "system", "inventory.error", map[string]any{"network_id": *j.NetworkID, "job_id": jobID, "error": err.Error()})
		} else if ips := newHostIPs(events); j.Kind == protocol.JobKindDiscovery && len(ips) > 0 {
			if err := s.scanNewHosts(ctx, *j.NetworkID, ips); err != nil {
				s.log.Error("port scan for new hosts", "network", *j.NetworkID, "err", err)
				_ = s.st.Audit(ctx, "system", "scheduler.error", map[string]any{"network_id": *j.NetworkID, "error": err.Error()})
			}
		}
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "accepted", "job_id": jobID})
}

func (s *Server) internalError(w http.ResponseWriter, err error) {
	s.log.Error("internal error", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

// ---- Admin API ----

type ctxKey struct{}

func adminFrom(ctx context.Context) store.Admin {
	a, _ := ctx.Value(ctxKey{}).(store.Admin)
	return a
}
