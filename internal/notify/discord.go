// Package notify sends change notifications to a Discord webhook.
//
// A webhook URL is a credential (whoever has it can post to the channel),
// so it never appears in errors or logs. Event texts may contain
// hostnames from reverse DNS, which any device on the network can choose;
// they are escaped and mentions are disabled.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Severities, lowest first.
var severities = []string{"info", "warning", "critical"}

// SeveritiesFrom returns min and all higher severities, or nil if min is
// unknown.
func SeveritiesFrom(min string) []string {
	for i, s := range severities {
		if s == min {
			return append([]string(nil), severities[i:]...)
		}
	}
	return nil
}

var discordHosts = map[string]bool{
	"discord.com": true, "discordapp.com": true, "ptb.discord.com": true, "canary.discord.com": true,
}

// ValidDiscordURL accepts only Discord webhook URLs
// (https://discord.com/api/webhooks/<id>/<token>), so the server cannot be
// pointed at internal addresses.
func ValidDiscordURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || !discordHosts[u.Hostname()] || u.Port() != "" || u.User != nil || u.Fragment != "" {
		return errors.New("not a Discord webhook URL (https://discord.com/api/webhooks/…)")
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "api" || parts[1] != "webhooks" || parts[2] == "" || parts[3] == "" {
		return errors.New("not a Discord webhook URL (https://discord.com/api/webhooks/<id>/<token>)")
	}
	if _, err := strconv.ParseUint(parts[2], 10, 64); err != nil {
		return errors.New("Discord webhook URL: invalid webhook id")
	}
	return nil
}

// Hint shows which webhook is configured without revealing its token.
func Hint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) < 3 {
		return ""
	}
	return "https://" + u.Hostname() + "/api/webhooks/" + parts[2] + "/••••"
}

// Item is one change to report.
type Item struct {
	At       time.Time
	Network  string
	IP       string
	Severity string
	Message  string
}

var severityText = map[string]string{"info": "🔵 Info", "warning": "🟠 Warnung", "critical": "🔴 Kritisch"}
var severityColor = map[string]int{"info": 0x3b82f6, "warning": 0xf59e0b, "critical": 0xdc2626}

// Discord limits: embed description 4096 characters.
const maxDescription = 3900

var markdownEscaper = strings.NewReplacer(
	`\`, `\\`, "*", `\*`, "_", `\_`, "~", `\~`, "`", "\\`", "|", `\|`, ">", `\>`, "#", `\#`, "[", `\[`, "]", `\]`,
	"@", "@​", // no mentions, even if allowed_mentions were ignored
)

// escape neutralizes Discord markdown and mentions and drops line breaks.
func escape(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 {
			return -1
		}
		return r
	}, s)
	return markdownEscaper.Replace(s)
}

type embed struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Color       int    `json:"color"`
	Timestamp   string `json:"timestamp,omitempty"`
	Footer      struct {
		Text string `json:"text"`
	} `json:"footer"`
}

type payload struct {
	Username        string  `json:"username"`
	Embeds          []embed `json:"embeds"`
	AllowedMentions struct {
		Parse []string `json:"parse"`
	} `json:"allowed_mentions"`
}

// Payload builds one Discord message for the items (oldest first). more
// is the number of further pending items not included.
func Payload(items []Item, more int) []byte {
	worst := 0
	var lines []string
	for _, it := range items {
		for i, s := range severities {
			if s == it.Severity && i > worst {
				worst = i
			}
		}
		line := fmt.Sprintf("%s · **%s** · `%s` – %s · %s",
			severityText[it.Severity], escape(it.Network), strings.ReplaceAll(it.IP, "`", ""), escape(it.Message),
			it.At.Local().Format("02.01. 15:04"))
		lines = append(lines, line)
	}
	desc, shown := "", 0
	for _, l := range lines {
		if len(desc)+len(l)+1 > maxDescription {
			break
		}
		desc += l + "\n"
		shown++
	}
	if rest := len(items) - shown + more; rest > 0 {
		desc += fmt.Sprintf("… und %d weitere (siehe Weboberfläche)", rest)
	}
	title := "NetCrawl: 1 Änderung"
	if n := len(items) + more; n != 1 {
		title = fmt.Sprintf("NetCrawl: %d Änderungen", n)
	}
	e := embed{Title: title, Description: strings.TrimSpace(desc), Color: severityColor[severities[worst]]}
	if len(items) > 0 {
		e.Timestamp = items[len(items)-1].At.UTC().Format(time.RFC3339)
	}
	e.Footer.Text = "NetCrawl"
	p := payload{Username: "NetCrawl", Embeds: []embed{e}}
	p.AllowedMentions.Parse = []string{}
	b, _ := json.Marshal(p)
	return b
}

// TestPayload is the message of the "send test" button.
func TestPayload(now time.Time) []byte {
	e := embed{Title: "NetCrawl: Testnachricht", Description: "Benachrichtigungen sind eingerichtet. Änderungen im Netz erscheinen ab jetzt hier.", Color: severityColor["info"], Timestamp: now.UTC().Format(time.RFC3339)}
	e.Footer.Text = "NetCrawl"
	p := payload{Username: "NetCrawl", Embeds: []embed{e}}
	p.AllowedMentions.Parse = []string{}
	b, _ := json.Marshal(p)
	return b
}

// RateLimitError means Discord asked to wait.
type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("Discord: rate limited, retry in %s", e.RetryAfter.Round(time.Second))
}

// Sender posts payloads to a webhook.
type Sender struct {
	HTTP *http.Client
}

// NewHTTPClient returns the client for webhook calls: environment proxy,
// timeout, no redirects.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Send posts a payload. Errors never contain the webhook URL.
func (s Sender) Send(ctx context.Context, webhookURL string, body []byte) error {
	if err := ValidDiscordURL(webhookURL); err != nil {
		return err
	}
	client := s.HTTP
	if client == nil {
		client = NewHTTPClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return errors.New("Discord: invalid request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "NetCrawl (notifications)")
	resp, err := client.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // url.Error would include the URL with its token
		}
		return fmt.Errorf("Discord unreachable: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusTooManyRequests:
		wait := 5 * time.Second
		var rl struct {
			RetryAfter float64 `json:"retry_after"`
		}
		if json.Unmarshal(data, &rl) == nil && rl.RetryAfter > 0 {
			wait = time.Duration(rl.RetryAfter * float64(time.Second))
		} else if v, err := strconv.ParseFloat(resp.Header.Get("Retry-After"), 64); err == nil && v > 0 {
			wait = time.Duration(v * float64(time.Second))
		}
		return &RateLimitError{RetryAfter: wait}
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized:
		return fmt.Errorf("Discord: webhook unknown or deleted (%d)", resp.StatusCode)
	default:
		var de struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &de)
		if de.Message != "" {
			return fmt.Errorf("Discord: %d %s", resp.StatusCode, escape(de.Message))
		}
		return fmt.Errorf("Discord: %d", resp.StatusCode)
	}
}
