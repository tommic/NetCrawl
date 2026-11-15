// Package protocol defines the wire format between netcrawl-server and
// netcrawl-agent: job and result documents, the request signature and the
// headers that carry it.
//
// Every agent request is signed with HMAC-SHA256 over a canonical string
// (see SigningString). Job polls are signed with the crawler's long-term
// secret. Result submissions are signed with the job's one-time result
// token, which the server hands out together with the job and which is
// never sent back; the server only accepts one result per token.
package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"netcrawler/internal/result"
)

// API paths.
const (
	PathJob       = "/api/v1/crawler/job"
	PathResultFmt = "/api/v1/crawler/jobs/%s/result"
)

// ResultPath returns the result submission path for a job.
func ResultPath(jobID string) string { return fmt.Sprintf(PathResultFmt, jobID) }

// Headers of a signed job poll.
const (
	HeaderCrawlerID        = "X-Crawler-Id"
	HeaderRequestNonce     = "X-Request-Nonce"
	HeaderRequestTimestamp = "X-Request-Timestamp"
	HeaderRequestHMAC      = "X-Request-HMAC"
)

// Headers of a signed result submission.
const (
	HeaderResultNonce     = "X-Result-Nonce"
	HeaderResultTimestamp = "X-Result-Timestamp"
	HeaderResultHMAC      = "X-Result-HMAC"
)

// MaxClockSkew is how far a request timestamp may deviate from the server
// clock. Nonces are remembered at least this long.
const MaxClockSkew = 5 * time.Minute

// SignatureScheme is the first line of every signing string.
const SignatureScheme = "NETCRAWL-HMAC-SHA256-V1"

// KeySize is the size in bytes of crawler secrets and result tokens.
const KeySize = 32

// Job is a scan order for one crawler.
type Job struct {
	JobID     string    `json:"job_id"`
	CrawlerID string    `json:"crawler_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Targets are IPv4 addresses, CIDRs or ranges.
	Targets   []string `json:"targets"`
	MaxHosts  int      `json:"max_hosts"`
	Ports     []int    `json:"ports"`
	TimeoutMs int      `json:"timeout_ms"`
	// Kind is JobKindPorts (report open ports) or JobKindDiscovery (report
	// which hosts are alive; open ports are a by-product). Empty means
	// JobKindPorts.
	Kind string `json:"kind,omitempty"`
	// Deny lists addresses/ranges inside Targets that must not be contacted.
	Deny []string `json:"deny,omitempty"`
	// ReverseDNS asks for PTR lookups of found hosts. The agent only does
	// them if its local config allows it.
	ReverseDNS bool `json:"reverse_dns,omitempty"`
	// ResultToken (base64url) is the HMAC key for this job's result. It is
	// valid for exactly one accepted result.
	ResultToken string `json:"result_token"`
}

// Job kinds.
const (
	JobKindPorts     = "ports"
	JobKindDiscovery = "discovery"
)

// Result is what an agent reports for a job.
type Result struct {
	JobID        string                 `json:"job_id"`
	CrawlerID    string                 `json:"crawler_id"`
	AgentVersion string                 `json:"agent_version"`
	Started      time.Time              `json:"started"`
	Finished     time.Time              `json:"finished"`
	Networks     []result.NetworkResult `json:"networks"`
}

// Error is the JSON body of every non-2xx API response.
type Error struct {
	Error string `json:"error"`
}

// SigningString builds the canonical string that is signed:
//
//	NETCRAWL-HMAC-SHA256-V1
//	<HTTP method>
//	<request path>
//	<crawler id>
//	<job id, empty for job polls>
//	<unix timestamp, seconds>
//	<nonce>
//	<lowercase hex SHA-256 of the unmodified request body>
//
// Lines are joined with "\n", without a trailing newline.
func SigningString(method, path, crawlerID, jobID string, timestamp int64, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	return strings.Join([]string{
		SignatureScheme,
		method,
		path,
		crawlerID,
		jobID,
		strconv.FormatInt(timestamp, 10),
		nonce,
		hex.EncodeToString(sum[:]),
	}, "\n")
}

// Sign returns the lowercase hex HMAC-SHA256 of the signing string.
func Sign(key []byte, signingString string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingString))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a hex signature in constant time.
func Verify(key []byte, signingString, signature string) bool {
	got, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(signingString))
	return hmac.Equal(got, mac.Sum(nil))
}

// NewKey returns KeySize random bytes.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// EncodeKey encodes a key as unpadded base64url.
func EncodeKey(k []byte) string { return base64.RawURLEncoding.EncodeToString(k) }

// DecodeKey decodes an unpadded base64url key and checks its size.
func DecodeKey(s string) ([]byte, error) {
	k, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("invalid key encoding: %w", err)
	}
	if len(k) != KeySize {
		return nil, fmt.Errorf("invalid key length %d, want %d bytes", len(k), KeySize)
	}
	return k, nil
}

// NewNonce returns a random 128-bit nonce as hex.
func NewNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// NewID returns a random UUIDv4 string.
func NewID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

// ValidJobID reports whether id is a lowercase UUID as produced by NewID.
// Agents check it before putting a server-supplied job ID into a URL path.
func ValidJobID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, r := range id {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
				return false
			}
		}
	}
	return true
}

// ValidNonce reports whether a nonce has an acceptable shape (16-128
// characters of [0-9a-zA-Z_-]).
func ValidNonce(n string) bool {
	if len(n) < 16 || len(n) > 128 {
		return false
	}
	for _, r := range n {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// ValidCrawlerID reports whether id is 1-64 characters of [a-z0-9._-],
// starting with a letter or digit.
func ValidCrawlerID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for i, r := range id {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if i > 0 {
			ok = ok || r == '.' || r == '_' || r == '-'
		}
		if !ok {
			return false
		}
	}
	return true
}

// ParseTimestamp parses a unix-seconds timestamp header and checks it is
// within MaxClockSkew of now.
func ParseTimestamp(value string, now time.Time) (int64, error) {
	ts, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, errors.New("invalid timestamp")
	}
	d := now.Sub(time.Unix(ts, 0))
	if d > MaxClockSkew || d < -MaxClockSkew {
		return 0, errors.New("timestamp outside allowed clock skew")
	}
	return ts, nil
}
