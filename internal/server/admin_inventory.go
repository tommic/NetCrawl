package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"netcrawler/internal/ports"
	"netcrawler/internal/servicecat"
	"netcrawler/internal/store"
)

func (s *Server) registerInventoryRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/admin/networks", s.admin(s.handleListNetworks))
	mux.Handle("POST /api/v1/admin/networks", s.admin(s.handleCreateNetwork))
	mux.Handle("PUT /api/v1/admin/networks/{id}", s.admin(s.handleUpdateNetwork))
	mux.Handle("POST /api/v1/admin/networks/{id}/scan", s.admin(s.handleScanNow))
	mux.Handle("GET /api/v1/admin/hosts", s.admin(s.handleListHosts))
	mux.Handle("POST /api/v1/admin/hosts/important", s.admin(s.handleSetImportant))
	mux.Handle("POST /api/v1/admin/hosts/name", s.admin(s.handleSetHostName))
	mux.Handle("GET /api/v1/admin/network-options", s.admin(s.handleNetworkOptions))
	mux.Handle("GET /api/v1/admin/events", s.admin(s.handleListEvents))
}

// NetworkView is the API representation of a network.
type NetworkView struct {
	ID                       int64      `json:"id"`
	CrawlerID                string     `json:"crawler_id"`
	Name                     string     `json:"name"`
	Targets                  []string   `json:"targets"`
	Deny                     []string   `json:"deny"`
	DiscoveryPorts           []int      `json:"discovery_ports"`
	ScanPorts                []int      `json:"scan_ports"`
	DiscoveryIntervalMinutes int        `json:"discovery_interval_minutes"`
	PortscanIntervalMinutes  int        `json:"portscan_interval_minutes"`
	PortscanIntervalHours    int        `json:"portscan_interval_hours"` // rounded down; use minutes
	ScanPreset               string     `json:"scan_preset"`
	OfflineInfoHours         int        `json:"offline_info_hours"`
	OfflineWarnHours         int        `json:"offline_warn_hours"`
	OfflineCriticalMinutes   int        `json:"offline_critical_minutes"`
	ServiceIntervalMinutes   int        `json:"service_interval_minutes"`
	LastServicesAt           *time.Time `json:"last_services_at,omitempty"`
	ReverseDNS               bool       `json:"reverse_dns"`
	Enabled                  bool       `json:"enabled"`
	CreatedAt                time.Time  `json:"created_at"`
	LastDiscoveryAt          *time.Time `json:"last_discovery_at,omitempty"`
	LastPortscanAt           *time.Time `json:"last_portscan_at,omitempty"`
	DiscoveryDoneAt          *time.Time `json:"discovery_done_at,omitempty"`
	PortscanDoneAt           *time.Time `json:"portscan_done_at,omitempty"`
	BaselineDone             bool       `json:"baseline_done"`
	Hosts                    int        `json:"hosts"`
	HostsOnline              int        `json:"hosts_online"`
}

func networkView(n store.Network, hosts []store.Host) NetworkView {
	v := NetworkView{
		ID: n.ID, CrawlerID: n.CrawlerID, Name: n.Name, Targets: n.Targets, Deny: n.Deny,
		DiscoveryPorts: n.DiscoveryPorts, ScanPorts: n.ScanPorts,
		DiscoveryIntervalMinutes: int(n.DiscoveryInterval.Minutes()),
		PortscanIntervalMinutes:  int(n.PortscanInterval.Minutes()),
		PortscanIntervalHours:    int(n.PortscanInterval.Hours()),
		ScanPreset:               scanPreset(n.ScanPorts),
		OfflineInfoHours:         int(n.OfflineInfoAfter.Hours()),
		OfflineWarnHours:         int(n.OfflineWarnAfter.Hours()),
		OfflineCriticalMinutes:   int(n.OfflineCriticalAfter.Minutes()),
		ServiceIntervalMinutes:   int(n.ServiceInterval.Minutes()),
		LastServicesAt:           n.LastServicesAt,
		ReverseDNS:               n.ReverseDNS, Enabled: n.Enabled, CreatedAt: n.CreatedAt,
		LastDiscoveryAt: n.LastDiscoveryAt, LastPortscanAt: n.LastPortscanAt,
		DiscoveryDoneAt: n.DiscoveryDoneAt, PortscanDoneAt: n.PortscanDoneAt, BaselineDone: n.BaselineDone,
	}
	if v.Deny == nil {
		v.Deny = []string{}
	}
	for _, h := range hosts {
		if h.NetworkID != n.ID {
			continue
		}
		v.Hosts++
		if h.OfflineLevel == "" {
			v.HostsOnline++
		}
	}
	return v
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeError(w, http.StatusNotFound, "network not found")
		return 0, false
	}
	return id, true
}

// PortPreset is one built-in port selection, as shown in the network form.
type PortPreset struct {
	Name  string `json:"name"`
	Ports []int  `json:"ports"`
}

// NetworkOptions is what the network form needs from the server: the
// built-in port presets and the defaults of a new network.
type NetworkOptions struct {
	Presets  []PortPreset `json:"presets"`
	Defaults NetworkView  `json:"defaults"`
}

func (s *Server) handleNetworkOptions(w http.ResponseWriter, _ *http.Request) {
	out := NetworkOptions{Presets: []PortPreset{}, Defaults: networkView(DefaultNetwork(), nil)}
	for _, name := range ports.Presets() {
		if list, ok := ports.Named(name); ok {
			out.Presets = append(out.Presets, PortPreset{Name: name, Ports: list})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleListNetworks(w http.ResponseWriter, r *http.Request) {
	networks, err := s.st.ListNetworks(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	hosts, err := s.st.Hosts(r.Context(), 0)
	if err != nil {
		s.internalError(w, err)
		return
	}
	out := make([]NetworkView, 0, len(networks))
	for _, n := range networks {
		out = append(out, networkView(n, hosts))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateNetwork(w http.ResponseWriter, r *http.Request) {
	var req NetworkRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	n, err := CreateNetwork(r.Context(), s.st, adminFrom(r.Context()).Username, req, s.now())
	if err != nil {
		s.serviceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, networkView(n, nil))
}

func (s *Server) handleUpdateNetwork(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req NetworkRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	n, err := UpdateNetwork(r.Context(), s.st, adminFrom(r.Context()).Username, id, req)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "network not found")
		return
	}
	if err != nil {
		s.serviceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, networkView(n, nil))
}

func (s *Server) handleScanNow(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req struct {
		Kind string `json:"kind"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	err := s.ScanNow(r.Context(), adminFrom(r.Context()).Username, id, req.Kind)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "network not found")
		return
	}
	if err != nil {
		s.serviceError(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "scheduled"})
}

// HostView is the API representation of an inventory entry.
type HostView struct {
	NetworkID      int64      `json:"network_id"`
	IP             string     `json:"ip"`
	Hostname       string     `json:"hostname"`
	CustomName     string     `json:"custom_name"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	Online         bool       `json:"online"`
	OfflineLevel   string     `json:"offline_level,omitempty"`
	Important      bool       `json:"important"`
	PortsScannedAt *time.Time `json:"ports_scanned_at,omitempty"`
	Ports          []PortView `json:"ports"`
}

// PortView is an open port of a host.
type PortView struct {
	Port      int          `json:"port"`
	FirstSeen time.Time    `json:"first_seen"`
	LastSeen  time.Time    `json:"last_seen"`
	Service   *ServiceView `json:"service,omitempty"`
}

// ServiceView is the identified service on a port.
type ServiceView struct {
	// Category groups services (web, remote, files, …); CategoryLabel is
	// its German name.
	Category      string     `json:"category"`
	CategoryLabel string     `json:"category_label"`
	Name          string     `json:"name"`
	Product       string     `json:"product"`
	Version       string     `json:"version"`
	Extra         string     `json:"extra"`
	Method        string     `json:"method"`
	SeenAt        *time.Time `json:"seen_at,omitempty"`
}

func (s *Server) handleListHosts(w http.ResponseWriter, r *http.Request) {
	nid, _ := strconv.ParseInt(r.URL.Query().Get("network_id"), 10, 64)
	hosts, err := s.st.Hosts(r.Context(), nid)
	if err != nil {
		s.internalError(w, err)
		return
	}
	out := make([]HostView, 0, len(hosts))
	for _, h := range hosts {
		v := HostView{
			NetworkID: h.NetworkID, IP: h.IP, Hostname: h.Hostname, CustomName: h.CustomName, FirstSeen: h.FirstSeen, LastSeen: h.LastSeen,
			Online: h.OfflineLevel == "", OfflineLevel: h.OfflineLevel, Important: h.Important,
			PortsScannedAt: h.PortsScannedAt, Ports: []PortView{},
		}
		for _, p := range h.Ports {
			pv := PortView{Port: p.Port, FirstSeen: p.FirstSeen, LastSeen: p.LastSeen}
			if sv := p.Service; sv.Name != "" {
				cat := servicecat.Of(sv.Name, sv.Product, p.Port)
				pv.Service = &ServiceView{Category: cat, CategoryLabel: servicecat.Labels[cat], Name: sv.Name, Product: sv.Product,
					Version: sv.Version, Extra: sv.Extra, Method: sv.Method, SeenAt: sv.SeenAt}
			}
			v.Ports = append(v.Ports, pv)
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleSetImportant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NetworkID int64  `json:"network_id"`
		IP        string `json:"ip"`
		Important bool   `json:"important"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	err := s.st.SetHostImportant(r.Context(), req.NetworkID, req.IP, req.Important)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.st.Audit(r.Context(), adminFrom(r.Context()).Username, "host.important", map[string]any{
		"network_id": req.NetworkID, "ip": req.IP, "important": req.Important,
	})
	w.WriteHeader(http.StatusNoContent)
}

// maxCustomNameLen is the longest custom host name (in characters).
const maxCustomNameLen = 64

// cleanCustomName trims a custom host name and rejects names that are too
// long or contain control characters.
func cleanCustomName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if utf8.RuneCountInString(name) > maxCustomNameLen {
		return "", invalid("name is longer than %d characters", maxCustomNameLen)
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", invalid("name must not contain control characters")
		}
	}
	return name, nil
}

func (s *Server) handleSetHostName(w http.ResponseWriter, r *http.Request) {
	var req struct {
		NetworkID int64  `json:"network_id"`
		IP        string `json:"ip"`
		Name      string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	name, err := cleanCustomName(req.Name)
	if err != nil {
		s.serviceError(w, err)
		return
	}
	err = s.st.SetHostCustomName(r.Context(), req.NetworkID, req.IP, name)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "host not found")
		return
	}
	if err != nil {
		s.internalError(w, err)
		return
	}
	_ = s.st.Audit(r.Context(), adminFrom(r.Context()).Username, "host.name", map[string]any{
		"network_id": req.NetworkID, "ip": req.IP, "name": name,
	})
	w.WriteHeader(http.StatusNoContent)
}

// EventView is the API representation of an inventory event.
type EventView struct {
	ID        int64           `json:"id"`
	At        time.Time       `json:"at"`
	NetworkID int64           `json:"network_id"`
	IP        string          `json:"ip,omitempty"`
	Type      string          `json:"type"`
	Severity  string          `json:"severity"`
	Message   string          `json:"message"`
	Details   json.RawMessage `json:"details"`
	JobID     string          `json:"job_id,omitempty"`
	Baseline  bool            `json:"baseline"`
}

func (s *Server) handleListEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	nid, _ := strconv.ParseInt(q.Get("network_id"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	events, err := s.st.ListEvents(r.Context(), store.EventFilter{
		NetworkID: nid, IP: q.Get("ip"), IncludeBaseline: q.Get("baseline") == "1", Limit: limit,
	})
	if err != nil {
		s.internalError(w, err)
		return
	}
	out := make([]EventView, 0, len(events))
	for _, e := range events {
		out = append(out, EventView{e.ID, e.At, e.NetworkID, e.IP, e.Type, e.Severity, e.Message, e.Details, e.JobID, e.Baseline})
	}
	writeJSON(w, http.StatusOK, out)
}
