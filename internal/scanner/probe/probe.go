// Package probe gathers optional service details for open ports found by
// the TCP connect scanner: TLS certificate metadata, HTTP title/Server
// header, and greeting banners from plain-text protocols. A missing or
// unreadable detail is not an error, it is simply omitted.
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// Info holds the service details gathered for a single open port.
type Info struct {
	Banner       string
	HTTPTitle    string
	HTTPServer   string
	TLSSubject   string
	TLSIssuer    string
	TLSNotAfter  string
	SSHKeyType   string
	SSHKeyFinger string
}

var (
	tlsPorts    = map[int]bool{443: true, 8443: true}
	httpPorts   = map[int]bool{80: true, 8000: true, 8080: true, 8081: true, 8888: true}
	bannerPorts = map[int]bool{21: true, 22: true, 25: true, 110: true, 143: true}
)

// Relevant reports whether port is a port probe knows how to enrich.
func Relevant(port int) bool {
	return tlsPorts[port] || httpPorts[port] || bannerPorts[port]
}

// Enrich probes the relevant open ports of hosts (address -> open ports, the
// same shape tcp.Scan returns) concurrently and returns per-host, per-port
// service details. Hosts/ports that don't answer, or that answer with
// nothing recognizable, are simply absent from the result.
func Enrich(ctx context.Context, hosts map[string][]int, timeout time.Duration, concurrency int) map[string]map[int]Info {
	type job struct {
		addr string
		port int
	}
	var jobs []job
	for addr, ports := range hosts {
		for _, port := range ports {
			if Relevant(port) {
				jobs = append(jobs, job{addr, port})
			}
		}
	}
	if len(jobs) == 0 {
		return nil
	}
	if concurrency < 1 {
		concurrency = 1
	}

	queue := make(chan job)
	result := make(map[string]map[int]Info)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range queue {
				info, ok := probeOne(ctx, j.addr, j.port, timeout)
				if !ok {
					continue
				}
				mu.Lock()
				if result[j.addr] == nil {
					result[j.addr] = map[int]Info{}
				}
				result[j.addr][j.port] = info
				mu.Unlock()
			}
		}()
	}
send:
	for _, j := range jobs {
		select {
		case queue <- j:
		case <-ctx.Done():
			break send
		}
	}
	close(queue)
	wg.Wait()
	return result
}

func probeOne(ctx context.Context, addr string, port int, timeout time.Duration) (Info, bool) {
	switch {
	case tlsPorts[port]:
		return probeTLS(ctx, addr, port, timeout)
	case httpPorts[port]:
		return probeHTTP(ctx, addr, port, timeout)
	case port == 22:
		// SSH gets both the raw greeting banner and the negotiated host
		// key, which need separate connections (the ssh package does its
		// own version exchange and would choke on a banner already read
		// off the same conn).
		info, bannerOK := probeBanner(ctx, addr, port, timeout)
		keyType, fingerprint, keyOK := probeSSHHostKey(ctx, addr, port, timeout)
		if !bannerOK && !keyOK {
			return Info{}, false
		}
		info.SSHKeyType = keyType
		info.SSHKeyFinger = fingerprint
		return info, true
	case bannerPorts[port]:
		return probeBanner(ctx, addr, port, timeout)
	}
	return Info{}, false
}

// errHostKeyCaptured aborts the SSH handshake right after the host key is
// seen, before any authentication is attempted.
var errHostKeyCaptured = errors.New("probe: host key captured")

// probeSSHHostKey negotiates just far enough into the SSH protocol to learn
// the server's host key, then aborts - no username, password, or key is
// ever sent, so this never attempts to log in.
func probeSSHHostKey(ctx context.Context, addr string, port int, timeout time.Duration) (keyType, fingerprint string, ok bool) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		return "", "", false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var hostKey ssh.PublicKey
	config := &ssh.ClientConfig{
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			hostKey = key
			return errHostKeyCaptured
		},
		Timeout: timeout,
	}
	// Always returns an error (either errHostKeyCaptured, or a transport
	// failure before the host key was even seen); only the former counts.
	_, _, _, _ = ssh.NewClientConn(conn, addr, config)
	if hostKey == nil {
		return "", "", false
	}
	return hostKey.Type(), ssh.FingerprintSHA256(hostKey), true
}

func probeTLS(ctx context.Context, addr string, port int, timeout time.Duration) (Info, bool) {
	d := net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		return Info{}, false
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(timeout))

	// InsecureSkipVerify is intentional: this only reads the certificate a
	// host presents for inventory purposes (e.g. spotting a router's admin
	// UI by its self-signed cert). Nothing is trusted or sent based on it,
	// so certificate validity is irrelevant here.
	conn := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	if err := conn.HandshakeContext(ctx); err != nil {
		return Info{}, false
	}
	var info Info
	if certs := conn.ConnectionState().PeerCertificates; len(certs) > 0 {
		cert := certs[0]
		info.TLSSubject = cert.Subject.CommonName
		info.TLSIssuer = cert.Issuer.CommonName
		info.TLSNotAfter = cert.NotAfter.Format("2006-01-02")
	}

	// Most services on 443/8443 are HTTPS, so also fetch title/Server over
	// the now-established TLS connection - that's usually the strongest
	// signal for what's actually behind the port (e.g. an admin UI's name).
	_ = raw.SetDeadline(time.Now().Add(timeout))
	info.HTTPTitle, info.HTTPServer = fetchHTTPInfo(conn, addr)

	if info == (Info{}) {
		return Info{}, false
	}
	return info, true
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// fetchHTTPInfo sends a plain GET / over conn (already connected, plaintext
// or TLS) and returns the page title and Server header, whichever it can
// find. Either return value may be empty; that's not treated as an error by
// callers.
func fetchHTTPInfo(conn net.Conn, host string) (title, server string) {
	req := "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: netcrawler\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", ""
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()

	server = resp.Header.Get("Server")
	body := make([]byte, 32*1024)
	n, _ := io.ReadFull(resp.Body, body)
	if m := titleRe.FindSubmatch(body[:n]); m != nil {
		title = strings.TrimSpace(strings.Join(strings.Fields(string(m[1])), " "))
	}
	return title, server
}

func probeHTTP(ctx context.Context, addr string, port int, timeout time.Duration) (Info, bool) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		return Info{}, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	title, server := fetchHTTPInfo(conn, addr)
	if title == "" && server == "" {
		return Info{}, false
	}
	return Info{HTTPTitle: title, HTTPServer: server}, true
}

// maxBannerBytes bounds how much of a greeting we ever read, so a server
// that never sends a line terminator can't make us buffer indefinitely.
const maxBannerBytes = 256

func probeBanner(ctx context.Context, addr string, port int, timeout time.Duration) (Info, bool) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		return Info{}, false
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	// Every protocol in bannerPorts sends exactly one plain-text greeting
	// line before switching to its (often binary) protocol proper - e.g.
	// SSH's version string is immediately followed by the binary KEXINIT
	// packet. Some servers (Dropbear in particular) send both in a single
	// TCP segment, so reading a fixed-size chunk can capture raw protocol
	// bytes along with the greeting. Reading only up to the first newline
	// avoids that.
	reader := bufio.NewReader(io.LimitReader(conn, maxBannerBytes))
	line, _ := reader.ReadString('\n')
	banner := sanitizeBanner(line)
	if banner == "" {
		return Info{}, false
	}
	return Info{Banner: banner}, true
}

// sanitizeBanner trims the line terminator and drops anything that isn't a
// printable character, in case a server's greeting is followed by (or is
// itself) binary protocol data rather than clean text.
func sanitizeBanner(line string) string {
	line = strings.TrimRight(line, "\r\n")
	var b strings.Builder
	for _, r := range line {
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}
