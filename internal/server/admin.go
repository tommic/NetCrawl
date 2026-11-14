package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"netcrawler/internal/store"
)

// SessionCookie is the admin session cookie name.
const SessionCookie = "netcrawl_session"

// MinPasswordLength is enforced when setting the admin password.
const MinPasswordLength = 12

// dummyHash is compared against when the user doesn't exist, so login
// timing doesn't reveal valid usernames.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("netcrawl-dummy-password"), bcrypt.DefaultCost)

// HashPassword returns a bcrypt hash after checking the minimum length.
func HashPassword(password string) (string, error) {
	if len(password) < MinPasswordLength {
		return "", invalid("password must be at least %d characters", MinPasswordLength)
	}
	if len(password) > 72 {
		return "", invalid("password must be at most 72 bytes")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// sessionToken extracts the token from the cookie or an
// "Authorization: Bearer" header.
func sessionToken(r *http.Request) (token string, fromCookie bool) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer "), false
	}
	if c, err := r.Cookie(SessionCookie); err == nil {
		return c.Value, true
	}
	return "", false
}

// isJSON reports whether the request declares a JSON body. Requiring it on
// cookie-authenticated writes blocks cross-site form posts (CSRF): browsers
// can't send application/json cross-origin without a CORS preflight.
func isJSON(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// admin wraps a handler that requires a valid admin session.
func (s *Server) admin(next func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, fromCookie := sessionToken(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "login required")
			return
		}
		if fromCookie && r.Method != http.MethodGet && !isJSON(r) {
			writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
			return
		}
		a, err := s.st.SessionAdmin(r.Context(), hashToken(token), s.now())
		if err != nil {
			writeError(w, http.StatusUnauthorized, "login required")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, a)))
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if !isJSON(r) {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	body, ok := readBody(w, r, maxSmallBodyBytes)
	if !ok {
		return false
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := clientIP(r)
	if wait := s.limiter.blocked(ip); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too many failed logins, try again later")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	a, err := s.st.AdminByUsername(ctx, req.Username)
	hash := []byte(a.PasswordHash)
	if err != nil {
		hash = dummyHash
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(req.Password)) != nil || err != nil {
		s.limiter.fail(ip)
		s.log.Warn("admin login failed", "username", req.Username, "remote", ip)
		_ = s.st.Audit(ctx, "anonymous", "admin.login.failed", map[string]string{"username": req.Username, "remote": ip})
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	s.limiter.reset(ip)

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		s.internalError(w, err)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	expires := s.now().Add(s.sessTTL)
	if err := s.st.CreateSession(ctx, hashToken(token), a.ID, expires); err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.st.Audit(ctx, a.Username, "admin.login", map[string]string{"remote": ip})
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: token, Path: "/", Expires: expires,
		HttpOnly: true, Secure: s.secure, SameSite: s.sameSite(),
	})
	writeJSON(w, http.StatusOK, map[string]any{"username": a.Username, "expires_at": expires.UTC()})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if token, _ := sessionToken(r); token != "" {
		_ = s.st.DeleteSession(r.Context(), hashToken(token))
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secure, SameSite: s.sameSite()})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"username": adminFrom(r.Context()).Username})
}

// CrawlerView is the API representation of a crawler (without secret).
type CrawlerView struct {
	ID         string     `json:"id"`
	Allow      []string   `json:"allow"`
	MaxHosts   int        `json:"max_hosts"`
	Enabled    bool       `json:"enabled"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
}

func crawlerView(c store.Crawler) CrawlerView {
	return CrawlerView{c.ID, c.Allow, c.MaxHosts, c.Enabled, c.CreatedAt, c.LastSeenAt}
}

func (s *Server) handleListCrawlers(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListCrawlers(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	out := make([]CrawlerView, 0, len(list))
	for _, c := range list {
		out = append(out, crawlerView(c))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateCrawler(w http.ResponseWriter, r *http.Request) {
	var req CrawlerRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	c, secret, err := CreateCrawler(r.Context(), s.st, adminFrom(r.Context()).Username, req, s.now())
	if err != nil {
		s.serviceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		CrawlerView
		Secret string `json:"secret"`
	}{crawlerView(c), secret})
}

// JobView is the API representation of a job (without result token).
type JobView struct {
	ID          string          `json:"id"`
	CrawlerID   string          `json:"crawler_id"`
	Targets     []string        `json:"targets"`
	Ports       []int           `json:"ports"`
	MaxHosts    int             `json:"max_hosts"`
	TimeoutMs   int             `json:"timeout_ms"`
	Status      string          `json:"status"`
	Expired     bool            `json:"expired"`
	CreatedBy   string          `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	ExpiresAt   time.Time       `json:"expires_at"`
	DeliveredAt *time.Time      `json:"delivered_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	Result      json.RawMessage `json:"result,omitempty"`
}

func (s *Server) jobView(j store.Job) JobView {
	return JobView{
		ID: j.ID, CrawlerID: j.CrawlerID, Targets: j.Targets, Ports: j.Ports, MaxHosts: j.MaxHosts,
		TimeoutMs: j.TimeoutMs, Status: j.Status,
		Expired:   j.Status != store.JobCompleted && !s.now().Before(j.ExpiresAt),
		CreatedBy: j.CreatedBy, CreatedAt: j.CreatedAt, ExpiresAt: j.ExpiresAt,
		DeliveredAt: j.DeliveredAt, CompletedAt: j.CompletedAt,
	}
}

func (s *Server) handleListJobs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	list, err := s.st.ListJobs(r.Context(), limit)
	if err != nil {
		s.internalError(w, err)
		return
	}
	out := make([]JobView, 0, len(list))
	for _, j := range list {
		out = append(out, s.jobView(j))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	var req JobRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	j, err := CreateJob(r.Context(), s.st, adminFrom(r.Context()).Username, req, s.now())
	if err != nil {
		s.serviceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.jobView(j))
}

func (s *Server) handleGetJob(w http.ResponseWriter, r *http.Request) {
	j, err := s.st.Job(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "job not found")
		return
	}
	if err != nil {
		s.internalError(w, err)
		return
	}
	v := s.jobView(j)
	if res, err := s.st.Result(r.Context(), j.ID); err == nil {
		v.Result = res.Body
	}
	writeJSON(w, http.StatusOK, v)
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	list, err := s.st.ListAudit(r.Context(), limit)
	if err != nil {
		s.internalError(w, err)
		return
	}
	type entry struct {
		ID      int64           `json:"id"`
		At      time.Time       `json:"at"`
		Actor   string          `json:"actor"`
		Action  string          `json:"action"`
		Details json.RawMessage `json:"details"`
	}
	out := make([]entry, 0, len(list))
	for _, e := range list {
		out = append(out, entry{e.ID, e.At, e.Actor, e.Action, e.Details})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) serviceError(w http.ResponseWriter, err error) {
	if IsValidation(err) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.internalError(w, err)
}

// loginLimiter blocks an IP for lockout after maxFailures failed logins
// within window.
type loginLimiter struct {
	mu       sync.Mutex
	now      func() time.Time
	failures map[string][]time.Time
}

const (
	maxLoginFailures = 5
	loginWindow      = 15 * time.Minute
)

func newLoginLimiter(now func() time.Time) *loginLimiter {
	return &loginLimiter{now: now, failures: map[string][]time.Time{}}
}

func (l *loginLimiter) recent(ip string) []time.Time {
	cutoff := l.now().Add(-loginWindow)
	var keep []time.Time
	for _, t := range l.failures[ip] {
		if t.After(cutoff) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.failures, ip)
	} else {
		l.failures[ip] = keep
	}
	return keep
}

func (l *loginLimiter) blocked(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	recent := l.recent(ip)
	if len(recent) < maxLoginFailures {
		return 0
	}
	return recent[len(recent)-maxLoginFailures].Add(loginWindow).Sub(l.now())
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failures[ip] = append(l.recent(ip), l.now())
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, ip)
}
