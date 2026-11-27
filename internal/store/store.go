// Package store defines the persistence interface of netcrawl-server.
// pgstore implements it with PostgreSQL; memstore keeps everything in
// memory for tests. Both must behave identically; storetest holds the
// shared conformance tests.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Errors returned by Store implementations.
var (
	ErrNotFound     = errors.New("not found")
	ErrExists       = errors.New("already exists")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrReplay       = errors.New("replay")
	ErrExpired      = errors.New("expired")
)

// Admin is a user of the admin API.
type Admin struct {
	ID           int64
	Username     string
	PasswordHash string
}

// Crawler is a registered agent.
type Crawler struct {
	ID string
	// Secret is the HMAC key for job polls.
	Secret []byte
	// Allow is the server-side allowlist for jobs of this crawler.
	Allow      []string
	MaxHosts   int
	Enabled    bool
	CreatedAt  time.Time
	LastSeenAt *time.Time
	// ReinstallRequired: the release was changed on the server and the
	// crawler still runs with its old local limits.
	ReinstallRequired bool
}

// Enrollment is a one-time code that installs a crawler. Only a SHA-256
// of the code is stored. Redeeming it sets a new crawler secret.
type Enrollment struct {
	TokenHash  []byte
	CrawlerID  string
	ReverseDNS bool
	CreatedAt  time.Time
	ExpiresAt  time.Time
	UsedAt     *time.Time
}

// Job states.
const (
	JobPending   = "pending"
	JobDelivered = "delivered"
	JobCompleted = "completed"
)

// Job is a scan order for one crawler.
type Job struct {
	ID        string
	CrawlerID string
	// NetworkID is set for jobs the scheduler created for a network.
	NetworkID *int64
	// Kind is "ports" or "discovery" (protocol.JobKind*).
	Kind        string
	Deny        []string
	ReverseDNS  bool
	Targets     []string
	Ports       []int
	MaxHosts    int
	TimeoutMs   int
	ResultToken []byte
	Status      string
	CreatedBy   string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	DeliveredAt *time.Time
	CompletedAt *time.Time
}

// Result is an accepted job result.
type Result struct {
	JobID      string
	CrawlerID  string
	ReceivedAt time.Time
	BodySHA256 []byte
	Body       json.RawMessage
}

// Submission is a signed result submission. Store.SubmitResult checks and
// records it atomically.
type Submission struct {
	CrawlerID string
	JobID     string
	Nonce     string
	Now       time.Time
	// Verify reports whether the request signature is valid for the job's
	// result token.
	Verify     func(resultToken []byte) bool
	Body       []byte
	BodySHA256 []byte
}

// Network is a scan area of one crawler with its schedule. The scheduler
// creates discovery and port scan jobs for it; results update the
// inventory.
type Network struct {
	ID                int64
	CrawlerID         string
	Name              string
	Targets           []string
	Deny              []string
	DiscoveryPorts    []int
	ScanPorts         []int
	DiscoveryInterval time.Duration
	PortscanInterval  time.Duration
	// A host not seen for OfflineInfoAfter / OfflineWarnAfter (measured
	// against completed discovery runs) raises an info / warning event.
	OfflineInfoAfter time.Duration
	OfflineWarnAfter time.Duration
	// An important host not seen for OfflineCriticalAfter raises a
	// critical event (usually much sooner than the warning).
	OfflineCriticalAfter time.Duration
	ReverseDNS           bool
	Enabled              bool
	CreatedAt            time.Time

	// Scheduling state, written by UpdateNetworkSchedule.
	LastDiscoveryAt *time.Time
	LastPortscanAt  *time.Time

	// Inventory state, written only via UpdateInventory.
	DiscoveryDoneAt *time.Time
	PortscanDoneAt  *time.Time
	BaselineDone    bool
}

// Host is an inventory entry: an address seen in a network.
type Host struct {
	NetworkID int64
	IP        string
	Hostname  string
	// CustomName is a name set by an administrator; it is shown instead
	// of the discovered hostname. Scan results never change it.
	CustomName string
	FirstSeen  time.Time
	LastSeen   time.Time
	Important  bool
	// OfflineLevel is "" while the host is considered present, otherwise
	// the severity of the last "offline" event raised for it.
	OfflineLevel string
	// PortsScannedAt is the last port scan that saw the host; nil means
	// no port baseline yet.
	PortsScannedAt *time.Time
	// Ports are the currently open ports, sorted by port.
	Ports []HostPort
}

// HostPort is a currently open port of a host.
type HostPort struct {
	Port      int
	FirstSeen time.Time
	LastSeen  time.Time
	// Service is what runs behind the port, from the last port scan that
	// could identify it (zero if never identified).
	Service Service
}

// Service is an identified service on a port.
type Service struct {
	Name    string // protocol, e.g. "ssh", "http"
	Product string // e.g. "OpenSSH"
	Version string // e.g. "9.6p1"
	Extra   string // e.g. "Ubuntu Linux; protocol 2.0"
	Method  string // "nmap" or "banner"
	// SeenAt is when it was last identified.
	SeenAt *time.Time
}

// Label is "OpenSSH 9.6p1", or the protocol name if the product is unknown.
func (s Service) Label() string {
	if s.Product == "" {
		return s.Name
	}
	if s.Version == "" {
		return s.Product
	}
	return s.Product + " " + s.Version
}

// Event severities.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Event is a detected change in the inventory.
type Event struct {
	ID        int64
	At        time.Time
	NetworkID int64
	IP        string
	Type      string
	Severity  string
	Message   string
	Details   json.RawMessage
	JobID     string
	// Baseline marks events of the initial inventory run.
	Baseline bool
}

// NotificationSettings configure change notifications (one set per
// server). The webhook URL is a credential: anyone who has it can post.
type NotificationSettings struct {
	DiscordURL string
	// MinSeverity is the lowest severity sent: info, warning or critical.
	MinSeverity string
	Enabled     bool
	// Since: only events at or after this time are sent, so enabling or
	// changing the settings does not send the whole history.
	Since      time.Time
	UpdatedAt  time.Time
	LastSentAt *time.Time
	LastError  string
}

// EventFilter selects events, newest first.
type EventFilter struct {
	NetworkID int64 // 0: all networks
	IP        string
	// IncludeBaseline also returns events of the initial inventory.
	IncludeBaseline bool
	Limit           int
}

// InventoryUpdate changes a network's inventory inside a transaction. It
// gets the network and all its hosts (keyed by IP), may modify both in
// place or add hosts to the map, and returns the IPs it changed and the
// events to record. Hosts not listed in changed are not written.
type InventoryUpdate func(n *Network, hosts map[string]*Host) (changed []string, events []Event, err error)

// AuditEntry records an administrative or security-relevant action.
type AuditEntry struct {
	ID      int64
	At      time.Time
	Actor   string
	Action  string
	Details json.RawMessage
}

// Store is the persistence interface of the server.
type Store interface {
	// SetAdmin creates the admin or replaces its password hash.
	SetAdmin(ctx context.Context, username, passwordHash string) error
	AdminByUsername(ctx context.Context, username string) (Admin, error)
	CreateSession(ctx context.Context, tokenHash []byte, adminID int64, expires time.Time) error
	// SessionAdmin returns the admin of an unexpired session.
	SessionAdmin(ctx context.Context, tokenHash []byte, now time.Time) (Admin, error)
	DeleteSession(ctx context.Context, tokenHash []byte) error

	CreateCrawler(ctx context.Context, c Crawler) error
	Crawler(ctx context.Context, id string) (Crawler, error)
	ListCrawlers(ctx context.Context) ([]Crawler, error)
	TouchCrawler(ctx context.Context, id string, now time.Time) error
	// SetCrawlerEnabled enables or disables (revokes) a crawler.
	SetCrawlerEnabled(ctx context.Context, id string, enabled bool) error
	// UpdateCrawlerRelease atomically sets a new allowlist and host limit,
	// marks the crawler as needing a reinstall and expires its open
	// (pending or delivered) jobs.
	UpdateCrawlerRelease(ctx context.Context, id string, allow []string, maxHosts int, now time.Time) error

	// Setting returns a server setting ("" if unset); SetSetting stores it.
	Setting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string, now time.Time) error

	// CreateEnrollment stores a one-time code and invalidates earlier
	// unused codes of the crawler. ErrNotFound if the crawler is unknown.
	CreateEnrollment(ctx context.Context, e Enrollment) error
	// Enrollment returns an unused, unexpired code, else ErrNotFound.
	Enrollment(ctx context.Context, tokenHash []byte, now time.Time) (Enrollment, error)
	// RedeemEnrollment atomically marks an unused, unexpired code as used,
	// replaces the crawler's secret and clears ReinstallRequired. ErrNotFound if the code is unknown,
	// used or expired; ErrForbidden if the crawler is disabled.
	RedeemEnrollment(ctx context.Context, tokenHash, newSecret []byte, now time.Time) (Crawler, Enrollment, error)

	// UseNonce records a nonce; ErrReplay if the crawler used it before.
	UseNonce(ctx context.Context, crawlerID, nonce string, now time.Time) error
	// PurgeNonces deletes nonces seen before the given time.
	PurgeNonces(ctx context.Context, before time.Time) error

	CreateJob(ctx context.Context, j Job) error
	Job(ctx context.Context, id string) (Job, error)
	ListJobs(ctx context.Context, limit int) ([]Job, error)
	// NextJob hands out the oldest pending, unexpired job of a crawler and
	// marks it delivered. ok is false if there is none.
	NextJob(ctx context.Context, crawlerID string, now time.Time) (j Job, ok bool, err error)

	// SubmitResult atomically checks a submission and stores the result.
	// Checks, in order: job exists (else ErrUnauthorized), belongs to the
	// crawler and was delivered (else ErrForbidden), signature valid
	// (ErrUnauthorized), no result yet and nonce unused (ErrReplay), job
	// not expired (ErrExpired).
	SubmitResult(ctx context.Context, s Submission) error
	Result(ctx context.Context, jobID string) (Result, error)

	CreateNetwork(ctx context.Context, n Network) (int64, error)
	Network(ctx context.Context, id int64) (Network, error)
	ListNetworks(ctx context.Context) ([]Network, error)
	// UpdateNetworkSettings writes the editable settings (name, targets,
	// deny, ports, intervals, thresholds, reverse DNS, enabled).
	UpdateNetworkSettings(ctx context.Context, n Network) error
	// UpdateNetworkSchedule records when jobs were last created.
	UpdateNetworkSchedule(ctx context.Context, id int64, lastDiscovery, lastPortscan *time.Time) error
	// OpenNetworkJobs counts pending or delivered, unexpired jobs of a
	// network and kind.
	OpenNetworkJobs(ctx context.Context, networkID int64, kind string, now time.Time) (int, error)

	// UpdateInventory runs fn atomically for one network (see
	// InventoryUpdate) and stores the changed hosts, the events and the
	// network's inventory state.
	UpdateInventory(ctx context.Context, networkID int64, fn InventoryUpdate) error
	// Hosts lists the inventory of a network (0: all networks), sorted by
	// network and numerically by IP.
	Hosts(ctx context.Context, networkID int64) ([]Host, error)
	SetHostImportant(ctx context.Context, networkID int64, ip string, important bool) error
	// SetHostCustomName sets (or with "" removes) a host's custom name.
	SetHostCustomName(ctx context.Context, networkID int64, ip, name string) error
	ListEvents(ctx context.Context, f EventFilter) ([]Event, error)

	// NotificationSettings returns the settings (zero value if none).
	NotificationSettings(ctx context.Context) (NotificationSettings, error)
	// SaveNotificationSettings stores URL, severity, enabled, since and
	// updated-at; it keeps LastSentAt and LastError.
	SaveNotificationSettings(ctx context.Context, n NotificationSettings) error
	// RecordNotification stores the outcome of the last delivery attempt.
	RecordNotification(ctx context.Context, sentAt *time.Time, lastError string) error
	// PendingEvents returns events not yet notified, without baseline
	// events, at or after since, with one of the severities, oldest first.
	PendingEvents(ctx context.Context, since time.Time, severities []string, limit int) ([]Event, error)
	MarkEventsNotified(ctx context.Context, ids []int64, at time.Time) error

	Audit(ctx context.Context, actor, action string, details any) error
	ListAudit(ctx context.Context, limit int) ([]AuditEntry, error)

	Close()
}

// MarshalDetails encodes audit details, falling back to null.
func MarshalDetails(details any) json.RawMessage {
	if details == nil {
		return json.RawMessage("null")
	}
	b, err := json.Marshal(details)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}
