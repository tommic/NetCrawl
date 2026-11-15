package server

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"netcrawler/internal/notify"
	"netcrawler/internal/store"
)

// Notification delivery: up to notifyBatch events per message; after a
// failure the next attempt waits notifyBackoffMin, doubling up to
// notifyBackoffMax (or what Discord asks for).
const (
	notifyBatch      = 25
	notifyBackoffMin = time.Minute
	notifyBackoffMax = 15 * time.Minute
)

type notifier struct {
	sender  notify.Sender
	mu      sync.Mutex
	retryAt time.Time
	backoff time.Duration
}

func (n *notifier) wait(now time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return now.Before(n.retryAt)
}

func (n *notifier) failed(now time.Time, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.backoff == 0 {
		n.backoff = notifyBackoffMin
	} else if n.backoff *= 2; n.backoff > notifyBackoffMax {
		n.backoff = notifyBackoffMax
	}
	wait := n.backoff
	var rl *notify.RateLimitError
	if errors.As(err, &rl) {
		wait = rl.RetryAfter + time.Second
	}
	n.retryAt = now.Add(wait)
}

func (n *notifier) ok() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.retryAt, n.backoff = time.Time{}, 0
}

// Notify sends pending events to Discord (one message, up to notifyBatch
// events) and marks them as notified. It is called by the scheduler.
func (s *Server) Notify(ctx context.Context) error {
	now := s.now()
	if s.notifier.wait(now) {
		return nil
	}
	set, err := s.st.NotificationSettings(ctx)
	if err != nil || !set.Enabled || set.DiscordURL == "" {
		return err
	}
	pending, err := s.st.PendingEvents(ctx, set.Since, notify.SeveritiesFrom(set.MinSeverity), notifyBatch+1)
	if err != nil || len(pending) == 0 {
		return err
	}
	more := 0
	if len(pending) > notifyBatch {
		pending, more = pending[:notifyBatch], 1 // at least one more; sent on the next run
	}
	names := map[int64]string{}
	if nets, err := s.st.ListNetworks(ctx); err == nil {
		for _, n := range nets {
			names[n.ID] = n.Name
		}
	}
	items := make([]notify.Item, 0, len(pending))
	ids := make([]int64, 0, len(pending))
	for _, e := range pending {
		items = append(items, notify.Item{At: e.At, Network: names[e.NetworkID], IP: e.IP, Severity: e.Severity, Message: e.Message})
		ids = append(ids, e.ID)
	}
	if err := s.notifier.sender.Send(ctx, set.DiscordURL, notify.Payload(items, more)); err != nil {
		s.notifier.failed(now, err)
		s.log.Warn("notification failed", "err", err)
		_ = s.st.RecordNotification(ctx, nil, err.Error())
		return nil
	}
	s.notifier.ok()
	if err := s.st.MarkEventsNotified(ctx, ids, now); err != nil {
		return err
	}
	return s.st.RecordNotification(ctx, &now, "")
}

// NotificationView is the API view of the settings; the webhook URL is
// never returned.
type NotificationView struct {
	DiscordConfigured bool       `json:"discord_configured"`
	DiscordHint       string     `json:"discord_hint,omitempty"`
	MinSeverity       string     `json:"min_severity"`
	Enabled           bool       `json:"enabled"`
	LastSentAt        *time.Time `json:"last_sent_at,omitempty"`
	LastError         string     `json:"last_error,omitempty"`
}

func notificationView(n store.NotificationSettings) NotificationView {
	v := NotificationView{DiscordConfigured: n.DiscordURL != "", DiscordHint: notify.Hint(n.DiscordURL), MinSeverity: n.MinSeverity,
		Enabled: n.Enabled, LastSentAt: n.LastSentAt, LastError: n.LastError}
	if v.MinSeverity == "" {
		v.MinSeverity = store.SeverityWarning
	}
	return v
}

// NotificationRequest changes the settings. An empty DiscordURL keeps the
// stored one; ClearDiscordURL removes it.
type NotificationRequest struct {
	DiscordURL      string `json:"discord_url"`
	ClearDiscordURL bool   `json:"clear_discord_url"`
	MinSeverity     string `json:"min_severity"`
	Enabled         bool   `json:"enabled"`
}

// UpdateNotifications validates and stores the settings. Only events from
// now on are sent, so enabling does not deliver the history.
func UpdateNotifications(ctx context.Context, st store.Store, actor string, req NotificationRequest, now time.Time) (store.NotificationSettings, error) {
	cur, err := st.NotificationSettings(ctx)
	if err != nil {
		return cur, err
	}
	if req.MinSeverity == "" {
		req.MinSeverity = store.SeverityWarning
	}
	if notify.SeveritiesFrom(req.MinSeverity) == nil {
		return cur, invalid("min_severity must be info, warning or critical")
	}
	url := cur.DiscordURL
	switch {
	case req.ClearDiscordURL:
		url = ""
	case req.DiscordURL != "":
		if err := notify.ValidDiscordURL(req.DiscordURL); err != nil {
			return cur, invalid("%v", err)
		}
		url = req.DiscordURL
	}
	if req.Enabled && url == "" {
		return cur, invalid("enter a Discord webhook URL first")
	}
	n := store.NotificationSettings{DiscordURL: url, MinSeverity: req.MinSeverity, Enabled: req.Enabled, Since: now.UTC(), UpdatedAt: now.UTC()}
	if err := st.SaveNotificationSettings(ctx, n); err != nil {
		return cur, err
	}
	_ = st.Audit(ctx, actor, "notifications.update", map[string]any{
		"enabled": n.Enabled, "min_severity": n.MinSeverity, "discord": notify.Hint(url), "url_changed": url != cur.DiscordURL,
	})
	n.LastSentAt, n.LastError = cur.LastSentAt, cur.LastError
	return n, nil
}

func (s *Server) registerNotifyRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/notifications", s.admin(func(w http.ResponseWriter, r *http.Request) {
		n, err := s.st.NotificationSettings(r.Context())
		if err != nil {
			s.internalError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, notificationView(n))
	}))
	mux.Handle("PUT /api/v1/admin/notifications", s.admin(func(w http.ResponseWriter, r *http.Request) {
		var req NotificationRequest
		if !decodeJSON(w, r, &req) {
			return
		}
		n, err := UpdateNotifications(r.Context(), s.st, adminFrom(r.Context()).Username, req, s.now())
		if err != nil {
			s.serviceError(w, err)
			return
		}
		s.notifier.ok()
		writeJSON(w, http.StatusOK, notificationView(n))
	}))
	mux.Handle("POST /api/v1/admin/notifications/test", s.admin(func(w http.ResponseWriter, r *http.Request) {
		n, err := s.st.NotificationSettings(r.Context())
		if err != nil {
			s.internalError(w, err)
			return
		}
		if n.DiscordURL == "" {
			writeError(w, http.StatusBadRequest, "no Discord webhook URL configured")
			return
		}
		_ = s.st.Audit(r.Context(), adminFrom(r.Context()).Username, "notifications.test", map[string]any{"discord": notify.Hint(n.DiscordURL)})
		if err := s.notifier.sender.Send(r.Context(), n.DiscordURL, notify.TestPayload(s.now())); err != nil {
			_ = s.st.RecordNotification(r.Context(), nil, err.Error())
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		now := s.now()
		_ = s.st.RecordNotification(r.Context(), &now, "")
		writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
	}))
}
