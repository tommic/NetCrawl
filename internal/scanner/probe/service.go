package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Service is what runs behind an open port.
type Service struct {
	Name    string // protocol, e.g. "ssh", "http", "https", "smtp"
	Product string // e.g. "OpenSSH", "nginx"
	Version string // e.g. "9.6p1"
	Extra   string // e.g. "Ubuntu Linux; protocol 2.0"
	Method  string // "nmap" or "banner"
}

// Services identifies the services on open ports (address -> ports).
// With nmapPath set it runs "nmap -sV" per host; ports nmap can't name,
// and every port without nmap, get the built-in banner/HTTP/TLS check.
// Ports where nothing is recognized are absent from the result.
func Services(ctx context.Context, hosts map[string][]int, nmapPath string, timeout time.Duration, concurrency int) map[string]map[int]Service {
	out := map[string]map[int]Service{}
	var mu sync.Mutex
	put := func(addr string, port int, s Service) {
		mu.Lock()
		defer mu.Unlock()
		if out[addr] == nil {
			out[addr] = map[int]Service{}
		}
		out[addr][port] = s
	}

	if nmapPath != "" {
		// nmap runs several probes per port itself; a few hosts at a time
		// is enough.
		forEach(ctx, keys(hosts), min(concurrency, 4), func(addr string) {
			for port, s := range nmapServices(ctx, nmapPath, addr, hosts[addr]) {
				put(addr, port, s)
			}
		})
	}

	type job struct {
		addr string
		port int
	}
	var jobs []job
	for addr, ports := range hosts {
		for _, port := range ports {
			if s, ok := out[addr][port]; !ok || s.Name == "" || s.Name == "unknown" {
				jobs = append(jobs, job{addr, port})
			}
		}
	}
	forEach(ctx, jobs, concurrency, func(j job) {
		if s, ok := identify(ctx, j.addr, j.port, timeout); ok {
			put(j.addr, j.port, s)
		}
	})
	return out
}

func keys(m map[string][]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// forEach runs fn for every item with at most n at a time.
func forEach[T any](ctx context.Context, items []T, n int, fn func(T)) {
	if n < 1 {
		n = 1
	}
	queue := make(chan T)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range queue {
				fn(it)
			}
		}()
	}
send:
	for _, it := range items {
		select {
		case queue <- it:
		case <-ctx.Done():
			break send
		}
	}
	close(queue)
	wg.Wait()
}

// identify is the built-in check: a greeting banner, else a TLS
// handshake (and HTTP inside it), else plain HTTP. TLS goes first because
// many HTTPS servers also answer plain HTTP (with an error page).
func identify(ctx context.Context, addr string, port int, timeout time.Duration) (Service, bool) {
	if raw, ok := readGreeting(ctx, addr, port, timeout); ok {
		if s, ok := matchGreeting(raw); ok {
			s.Method = "banner"
			return s, true
		}
	}
	if s, ok := identifyHTTP(ctx, addr, port, timeout, true); ok {
		return s, true
	}
	return identifyHTTP(ctx, addr, port, timeout, false)
}

func dial(ctx context.Context, addr string, port int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

// readGreeting returns what a server sends on its own right after the
// connect (SSH, FTP, SMTP, POP3, IMAP, MySQL do).
func readGreeting(ctx context.Context, addr string, port int, timeout time.Duration) ([]byte, bool) {
	conn, err := dial(ctx, addr, port, timeout)
	if err != nil {
		return nil, false
	}
	defer conn.Close()
	buf := make([]byte, maxBannerBytes)
	n, _ := io.ReadAtLeast(conn, buf, 1)
	return buf[:n], n > 0
}

func identifyHTTP(ctx context.Context, addr string, port int, timeout time.Duration, useTLS bool) (Service, bool) {
	conn, err := dial(ctx, addr, port, timeout)
	if err != nil {
		return Service{}, false
	}
	defer conn.Close()
	name := "http"
	if useTLS {
		// Only reads what the host presents; nothing is trusted (see probeTLS).
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		if err := tc.HandshakeContext(ctx); err != nil {
			return Service{}, false
		}
		conn, name = tc, "https"
	}
	_, server, ok := httpResponse(conn, addr)
	if !ok {
		if useTLS {
			return Service{Name: "ssl", Method: "banner"}, true
		}
		return Service{}, false
	}
	s := parseServerHeader(server)
	s.Name, s.Method = name, "banner"
	return s, true
}

// httpResponse is fetchHTTPInfo that also tells whether any HTTP answer came.
func httpResponse(conn net.Conn, host string) (title, server string, ok bool) {
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: netcrawler\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", "", false
	}
	r := bufio.NewReader(conn)
	head, err := r.Peek(5)
	if err != nil || string(head) != "HTTP/" {
		return "", "", false
	}
	title, server = fetchHTTPInfoFrom(r)
	return title, server, true
}

var serverRe = regexp.MustCompile(`^([^/\s(]+)(?:/(\S+))?\s*(?:\((.*?)\))?`)

// parseServerHeader reads "nginx/1.24.0 (Ubuntu)" into product, version
// and extra info.
func parseServerHeader(h string) Service {
	m := serverRe.FindStringSubmatch(strings.TrimSpace(h))
	if m == nil {
		return Service{}
	}
	return Service{Product: m[1], Version: m[2], Extra: m[3]}
}

var greetings = []struct {
	re                   *regexp.Regexp
	name, product, extra string // product "" = from the first group
}{
	{regexp.MustCompile(`^SSH-[\d.]+-OpenSSH_(\S+)(?:\s+(.*))?`), "ssh", "OpenSSH", ""},
	{regexp.MustCompile(`^SSH-[\d.]+-dropbear_(\S+)`), "ssh", "Dropbear", ""},
	{regexp.MustCompile(`^SSH-[\d.]+-(\S+)`), "ssh", "", ""},
	{regexp.MustCompile(`^220[ -].*ProFTPD\s+([\d.]+\w*)`), "ftp", "ProFTPD", ""},
	{regexp.MustCompile(`^220[ -].*\(vsFTPd\s+([\d.]+)\)`), "ftp", "vsftpd", ""},
	{regexp.MustCompile(`^220[ -].*Pure-FTPd`), "ftp", "Pure-FTPd", ""},
	{regexp.MustCompile(`^220[ -].*FileZilla Server\s*([\d.]+)?`), "ftp", "FileZilla Server", ""},
	{regexp.MustCompile(`^220[ -].*E?SMTP\s+Postfix`), "smtp", "Postfix", ""},
	{regexp.MustCompile(`^220[ -].*E?SMTP\s+Exim\s+([\d.]+)`), "smtp", "Exim", ""},
	{regexp.MustCompile(`^220[ -].*E?SMTP\s+Sendmail\s+([\d./]+)`), "smtp", "Sendmail", ""},
	{regexp.MustCompile(`^220[ -].*E?SMTP`), "smtp", "-", ""},
	{regexp.MustCompile(`^220[ -].*FTP`), "ftp", "-", ""},
	{regexp.MustCompile(`^\+OK.*Dovecot`), "pop3", "Dovecot", ""},
	{regexp.MustCompile(`^\+OK`), "pop3", "-", ""},
	{regexp.MustCompile(`^\* OK.*Dovecot`), "imap", "Dovecot", ""},
	{regexp.MustCompile(`^\* OK`), "imap", "-", ""},
}

// matchGreeting recognizes a greeting. Product "-" means the protocol is
// known but not the software.
func matchGreeting(raw []byte) (Service, bool) {
	if s, ok := mysqlGreeting(raw); ok {
		return s, true
	}
	line := sanitizeBanner(string(bytes.SplitN(raw, []byte("\n"), 2)[0]))
	if line == "" {
		return Service{}, false
	}
	for _, g := range greetings {
		m := g.re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		s := Service{Name: g.name, Product: g.product}
		switch {
		case g.product == "" && len(m) > 1:
			// "SSH-2.0-Foo_1.2": product and version from one token.
			s.Product, s.Version, _ = strings.Cut(m[1], "_")
		case len(m) > 1:
			s.Version = m[1]
		}
		if len(m) > 2 {
			s.Extra = m[2]
		}
		if s.Product == "-" {
			s.Product = ""
		}
		return s, true
	}
	return Service{Name: "unknown", Extra: line}, true
}

var versionRe = regexp.MustCompile(`^\d+\.\d+`)

// mysqlGreeting reads the MySQL/MariaDB handshake: 4 header bytes,
// protocol version 10, then the server version as a C string.
func mysqlGreeting(raw []byte) (Service, bool) {
	if len(raw) < 6 || raw[4] != 0x0a {
		return Service{}, false
	}
	end := bytes.IndexByte(raw[5:], 0)
	if end <= 0 {
		return Service{}, false
	}
	v := string(raw[5 : 5+end])
	if !versionRe.MatchString(v) {
		return Service{}, false
	}
	s := Service{Name: "mysql", Product: "MySQL", Version: v}
	if i := strings.Index(v, "-MariaDB"); i >= 0 {
		s.Product, s.Version = "MariaDB", strings.TrimPrefix(v[:i], "5.5.5-")
	}
	return s, true
}
