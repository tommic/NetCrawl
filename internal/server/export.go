package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"netcrawler/internal/protocol"
	"netcrawler/internal/result"
	"netcrawler/internal/store"
	"netcrawler/internal/version"
)

// ExportTokenPrefix marks export read tokens ("nce_" + 43 base64url
// characters), so they can't be mixed up with admin session tokens.
const ExportTokenPrefix = "nce_"

// Export limits: event history in days (default and maximum) and the
// number of events listed.
const (
	DefaultExportDays = 7
	MaxExportDays     = 90
	maxExportEvents   = 300
)

func (s *Server) registerExportRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/export.txt", s.handleExportText)
	mux.Handle("GET /api/v1/admin/export-tokens", s.admin(s.handleListExportTokens))
	mux.Handle("POST /api/v1/admin/export-tokens", s.admin(s.handleCreateExportToken))
	mux.Handle("DELETE /api/v1/admin/export-tokens/{id}", s.admin(s.handleDeleteExportToken))
}

// ExportTokenView describes a read token; Token is only set right after
// creation (it is not stored).
type ExportTokenView struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Token      string     `json:"token,omitempty"`
}

func (s *Server) handleListExportTokens(w http.ResponseWriter, r *http.Request) {
	list, err := s.st.ListExportTokens(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	out := make([]ExportTokenView, 0, len(list))
	for _, t := range list {
		out = append(out, ExportTokenView{ID: t.ID, Name: t.Name, CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt, LastUsedAt: t.LastUsedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateExportToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len([]rune(name)) > 64 || strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		writeError(w, http.StatusBadRequest, "name must be 1-64 characters")
		return
	}
	key, err := protocol.NewKey()
	if err != nil {
		s.internalError(w, err)
		return
	}
	token := ExportTokenPrefix + protocol.EncodeKey(key)
	actor := adminFrom(r.Context()).Username
	now := s.now().UTC()
	id, err := s.st.CreateExportToken(r.Context(), store.ExportToken{Name: name, TokenHash: hashToken(token), CreatedBy: actor, CreatedAt: now})
	if err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.st.Audit(r.Context(), actor, "export_token.create", map[string]any{"id": id, "name": name})
	writeJSON(w, http.StatusCreated, ExportTokenView{ID: id, Name: name, CreatedBy: actor, CreatedAt: now, Token: token})
}

func (s *Server) handleDeleteExportToken(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusNotFound, "unknown token")
		return
	}
	if err := s.st.DeleteExportToken(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "unknown token")
			return
		}
		s.internalError(w, err)
		return
	}
	_ = s.st.Audit(r.Context(), adminFrom(r.Context()).Username, "export_token.delete", map[string]any{"id": id})
	w.WriteHeader(http.StatusNoContent)
}

// exportAllowed accepts an export token (Authorization: Bearer nce_… or
// ?token=nce_…) or an admin session (web UI download).
func (s *Server) exportAllowed(r *http.Request) bool {
	token := r.URL.Query().Get("token")
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		token = strings.TrimPrefix(h, "Bearer ")
	}
	if strings.HasPrefix(token, ExportTokenPrefix) {
		_, err := s.st.UseExportToken(r.Context(), hashToken(token), s.now())
		return err == nil
	}
	if session, _ := sessionToken(r); session != "" {
		_, err := s.st.SessionAdmin(r.Context(), hashToken(session), s.now())
		return err == nil
	}
	return false
}

func (s *Server) handleExportText(w http.ResponseWriter, r *http.Request) {
	if !s.exportAllowed(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="netcrawl-export"`)
		writeError(w, http.StatusUnauthorized, "export token or login required")
		return
	}
	days := DefaultExportDays
	if v := r.URL.Query().Get("days"); v != "" {
		d, err := strconv.Atoi(v)
		if err != nil || d < 0 || d > MaxExportDays {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("days must be 0-%d", MaxExportDays))
			return
		}
		days = d
	}
	var networkID int64
	if v := r.URL.Query().Get("network_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id < 1 {
			writeError(w, http.StatusBadRequest, "invalid network_id")
			return
		}
		networkID = id
	}
	text, err := BuildExport(r.Context(), s.st, ExportOptions{NetworkID: networkID, Days: days}, s.now())
	if err != nil {
		s.internalError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="netcrawl-inventar.txt"`)
	}
	_, _ = w.Write([]byte(text))
}

// ExportOptions select what the export contains.
type ExportOptions struct {
	NetworkID int64 // 0: all networks
	Days      int   // event history; 0: no events
}

// BuildExport writes the inventory as plain text for people and language
// models: networks, devices with open ports and services, software
// overview, recent changes. Times are UTC.
func BuildExport(ctx context.Context, st store.Store, opt ExportOptions, now time.Time) (string, error) {
	networks, err := st.ListNetworks(ctx)
	if err != nil {
		return "", err
	}
	hosts, err := st.Hosts(ctx, opt.NetworkID)
	if err != nil {
		return "", err
	}
	byNet := map[int64][]store.Host{}
	for _, h := range hosts {
		byNet[h.NetworkID] = append(byNet[h.NetworkID], h)
	}

	var b strings.Builder
	stamp := func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") }
	opt2 := func(t *time.Time) string {
		if t == nil {
			return "noch nie"
		}
		return stamp(*t)
	}
	fmt.Fprintf(&b, "# NetCrawl-Inventar\n")
	fmt.Fprintf(&b, "Stand: %s UTC · NetCrawl %s\n", stamp(now), version.Version)
	fmt.Fprintf(&b, "Inhalt: Netze, Geräte mit offenen Ports und erkannten Diensten, Software-Übersicht, Änderungen der letzten %d Tage.\n", opt.Days)
	fmt.Fprintf(&b, "Hinweise: \"wichtig\" = vom Admin als wichtig markiert; \"offline\" = in der letzten Host-Erkennung nicht gesehen; Dienste/Versionen per nmap -sV oder Banner.\n")

	var shown []store.Network
	for _, n := range networks {
		if opt.NetworkID == 0 || n.ID == opt.NetworkID {
			shown = append(shown, n)
		}
	}

	b.WriteString("\n## Netze\n")
	if len(shown) == 0 {
		b.WriteString("(keine)\n")
	}
	for _, n := range shown {
		online := 0
		for _, h := range byNet[n.ID] {
			if h.OfflineLevel == "" {
				online++
			}
		}
		state := ""
		if !n.Enabled {
			state = " · deaktiviert"
		}
		fmt.Fprintf(&b, "- %s: %s", n.Name, strings.Join(n.Targets, ", "))
		if len(n.Deny) > 0 {
			fmt.Fprintf(&b, " (ohne %s)", strings.Join(n.Deny, ", "))
		}
		devices := "Geräte"
		if len(byNet[n.ID]) == 1 {
			devices = "Gerät"
		}
		fmt.Fprintf(&b, " · Crawler %s · %d %s, %d online%s\n", n.CrawlerID, len(byNet[n.ID]), devices, online, state)
		fmt.Fprintf(&b, "  Letzte Host-Erkennung %s, letzter Portscan %s\n", opt2(n.DiscoveryDoneAt), opt2(n.PortscanDoneAt))
	}

	type swKey struct{ name, product, version string }
	software := map[swKey][]string{}
	for _, n := range shown {
		fmt.Fprintf(&b, "\n## Geräte in %s\n", n.Name)
		list := byNet[n.ID]
		sort.Slice(list, func(i, j int) bool { return result.CompareIPs(list[i].IP, list[j].IP) < 0 })
		if len(list) == 0 {
			b.WriteString("(noch keine gefunden)\n")
		}
		for _, h := range list {
			name := h.CustomName
			if name == "" {
				name = h.Hostname
			}
			line := h.IP
			if name != "" {
				line += " " + name
			}
			if h.CustomName != "" && h.Hostname != "" && h.Hostname != h.CustomName {
				line += " (DNS: " + h.Hostname + ")"
			}
			status := "online"
			if h.OfflineLevel != "" {
				status = "offline seit " + stamp(h.LastSeen)
			}
			line += " · " + status
			if h.Important {
				line += " · wichtig"
			}
			line += " · zuerst gesehen " + stamp(h.FirstSeen)
			fmt.Fprintf(&b, "- %s\n", line)
			switch {
			case h.PortsScannedAt == nil:
				b.WriteString("  Ports: noch kein Portscan\n")
			case len(h.Ports) == 0:
				b.WriteString("  Ports: keine offen\n")
			default:
				for _, p := range h.Ports {
					sv := p.Service
					desc := ""
					if sv.Name != "" {
						desc = sv.Name
						if l := sv.Label(); l != sv.Name {
							desc += ", " + l
						}
						if sv.Extra != "" {
							desc += " (" + sv.Extra + ")"
						}
						key := swKey{sv.Name, sv.Product, sv.Version}
						software[key] = append(software[key], h.IP+":"+strconv.Itoa(p.Port))
					}
					if desc == "" {
						desc = "Dienst unbekannt"
					}
					fmt.Fprintf(&b, "  %d/tcp %s\n", p.Port, desc)
				}
			}
		}
	}

	b.WriteString("\n## Software-Übersicht\n")
	if len(software) == 0 {
		b.WriteString("(noch keine Dienste erkannt)\n")
	}
	keys := make([]swKey, 0, len(software))
	for k := range software {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, c := keys[i], keys[j]
		if (a.product == "") != (c.product == "") {
			return a.product != ""
		}
		if a.product != c.product {
			return strings.ToLower(a.product) < strings.ToLower(c.product)
		}
		if a.version != c.version {
			return a.version < c.version
		}
		return a.name < c.name
	})
	for _, k := range keys {
		label := k.product
		if label == "" {
			label = "unbekannte Software"
		}
		if k.version != "" {
			label += " " + k.version
		}
		fmt.Fprintf(&b, "- %s [%s]: %s\n", label, k.name, strings.Join(software[k], ", "))
	}

	if opt.Days > 0 {
		fmt.Fprintf(&b, "\n## Änderungen der letzten %d Tage (neueste zuerst)\n", opt.Days)
		events, err := st.ListEvents(ctx, store.EventFilter{NetworkID: opt.NetworkID, Limit: maxExportEvents})
		if err != nil {
			return "", err
		}
		since := now.Add(-time.Duration(opt.Days) * 24 * time.Hour)
		n := 0
		for _, e := range events {
			if e.At.Before(since) {
				break
			}
			fmt.Fprintf(&b, "- %s %s: %s\n", stamp(e.At), severityText(e.Severity), e.Message)
			n++
		}
		if n == 0 {
			b.WriteString("(keine)\n")
		}
	}
	return b.String(), nil
}

func severityText(s string) string {
	switch s {
	case store.SeverityCritical:
		return "KRITISCH"
	case store.SeverityWarning:
		return "Warnung"
	default:
		return "Info"
	}
}
