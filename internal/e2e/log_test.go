package e2e

import (
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
)

type slogLogger = slog.Logger

func newDiscardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// cookieJar is a minimal jar for the admin session (net/http/cookiejar
// would work too; this keeps cookies for any URL of the test server).
type cookieJar struct {
	mu      sync.Mutex
	cookies []*http.Cookie
}

func (j *cookieJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies = append(j.cookies, cookies...)
}

func (j *cookieJar) Cookies(*url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cookies
}
