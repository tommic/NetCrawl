package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const hook = "https://discord.com/api/webhooks/123456789012345678/SECRET-token_abc"

func TestValidDiscordURL(t *testing.T) {
	ok := []string{hook, "https://discordapp.com/api/webhooks/1/x", "https://canary.discord.com/api/webhooks/1/x?wait=true"}
	bad := []string{"", "http://discord.com/api/webhooks/1/x", "https://discord.com.evil.org/api/webhooks/1/x",
		"https://evil.org/api/webhooks/1/x", "https://192.168.1.1/api/webhooks/1/x", "https://discord.com/api/webhooks/1",
		"https://discord.com/api/webhooks/abc/x", "https://discord.com:8443/api/webhooks/1/x", "https://u:p@discord.com/api/webhooks/1/x"}
	for _, u := range ok {
		if err := ValidDiscordURL(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range bad {
		if err := ValidDiscordURL(u); err == nil {
			t.Errorf("%s accepted", u)
		}
	}
	if h := Hint(hook); h != "https://discord.com/api/webhooks/123456789012345678/••••" || strings.Contains(h, "SECRET") {
		t.Errorf("hint %q", h)
	}
}

func TestSeveritiesFrom(t *testing.T) {
	if got := strings.Join(SeveritiesFrom("warning"), ","); got != "warning,critical" {
		t.Errorf("warning: %s", got)
	}
	if SeveritiesFrom("x") != nil {
		t.Error("unknown accepted")
	}
}

type decoded struct {
	Username        string `json:"username"`
	AllowedMentions struct {
		Parse []string `json:"parse"`
	} `json:"allowed_mentions"`
	Embeds []struct {
		Title, Description string
		Color              int
	} `json:"embeds"`
}

func TestPayloadEscapesAndLimits(t *testing.T) {
	at := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	items := []Item{
		{At: at, Network: "Heimnetz", IP: "192.168.1.20", Severity: "warning", Message: "Port 22 neu offen auf 192.168.1.20"},
		{At: at, Network: "Heimnetz", IP: "192.168.1.30", Severity: "info", Message: "Hostname geändert: @everyone **x** [link](http://e.vil)\nzweite Zeile"},
		{At: at, Network: "Heimnetz", IP: "192.168.1.40", Severity: "critical", Message: "Host seit 7 Tagen nicht gesehen"},
	}
	var p decoded
	if err := json.Unmarshal(Payload(items, 2), &p); err != nil {
		t.Fatal(err)
	}
	if p.AllowedMentions.Parse == nil || len(p.AllowedMentions.Parse) != 0 {
		t.Fatalf("allowed_mentions must be an empty list: %+v", p.AllowedMentions)
	}
	e := p.Embeds[0]
	if e.Title != "NetCrawl: 5 Änderungen" || e.Color != severityColor["critical"] {
		t.Errorf("title/color: %q %x", e.Title, e.Color)
	}
	if strings.Contains(e.Description, "@everyone") || strings.Contains(e.Description, "**x**") || strings.Contains(e.Description, "[link]") {
		t.Errorf("not escaped: %s", e.Description)
	}
	if strings.Count(e.Description, "\n") != 3 || !strings.HasSuffix(e.Description, "… und 2 weitere (siehe Weboberfläche)") {
		t.Errorf("lines: %q", e.Description)
	}

	// Many items are cut at Discord's limit and counted.
	var many []Item
	for i := 0; i < 200; i++ {
		many = append(many, Item{At: at, Network: "N", IP: "10.0.0.1", Severity: "warning", Message: strings.Repeat("x", 60)})
	}
	if err := json.Unmarshal(Payload(many, 0), &p); err != nil {
		t.Fatal(err)
	}
	if d := p.Embeds[0].Description; len(d) > 4096 || !strings.Contains(d, "weitere") {
		t.Errorf("long description: %d bytes", len(d))
	}
}

// redirect sends all requests to the test server, keeping the path.
type redirect struct{ target *url.URL }

func (r redirect) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = r.target.Scheme, r.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func TestSend(t *testing.T) {
	var status int
	var body string
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	target, _ := url.Parse(srv.URL)
	s := Sender{HTTP: &http.Client{Transport: redirect{target}}}
	ctx := context.Background()

	status = http.StatusNoContent
	if err := s.Send(ctx, hook, TestPayload(time.Now())); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/api/webhooks/123456789012345678/SECRET-token_abc" || !strings.Contains(gotBody, "Testnachricht") {
		t.Fatalf("request %s %s", gotPath, gotBody)
	}

	status, body = http.StatusTooManyRequests, `{"retry_after": 2.5}`
	var rl *RateLimitError
	if err := s.Send(ctx, hook, []byte("{}")); err == nil || !asRateLimit(err, &rl) || rl.RetryAfter != 2500*time.Millisecond {
		t.Fatalf("429: %v", err)
	}
	status, body = http.StatusNotFound, `{"message":"Unknown Webhook"}`
	if err := s.Send(ctx, hook, []byte("{}")); err == nil || !strings.Contains(err.Error(), "unknown or deleted") {
		t.Fatalf("404: %v", err)
	}
	status, body = http.StatusBadRequest, `{"message":"Invalid Form Body"}`
	if err := s.Send(ctx, hook, []byte("{}")); err == nil || !strings.Contains(err.Error(), "400 Invalid Form Body") {
		t.Fatalf("400: %v", err)
	}

	// Network errors must not leak the token.
	srv.Close()
	err := s.Send(ctx, hook, []byte("{}"))
	if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "webhooks") {
		t.Fatalf("network error leaks URL: %v", err)
	}
	if err := s.Send(ctx, "https://evil.org/api/webhooks/1/x", []byte("{}")); err == nil {
		t.Fatal("non-Discord URL sent")
	}
}

func asRateLimit(err error, target **RateLimitError) bool {
	rl, ok := err.(*RateLimitError)
	*target = rl
	return ok
}
