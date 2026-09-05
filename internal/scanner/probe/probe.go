// Package probe gathers optional service details for open ports found by
// the TCP connect scanner: TLS certificate metadata, HTTP title/Server
// header, and greeting banners from plain-text protocols. A missing or
// unreadable detail is not an error, it is simply omitted.
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Info holds the service details gathered for a single open port.
type Info struct {
	Banner      string
	HTTPTitle   string
	HTTPServer  string
	TLSSubject  string
	TLSIssuer   string
	TLSNotAfter string
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
	case bannerPorts[port]:
		return probeBanner(ctx, addr, port, timeout)
	}
	return Info{}, false
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
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return Info{}, false
	}
	cert := certs[0]
	return Info{
		TLSSubject:  cert.Subject.CommonName,
		TLSIssuer:   cert.Issuer.CommonName,
		TLSNotAfter: cert.NotAfter.Format("2006-01-02"),
	}, true
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func probeHTTP(ctx context.Context, addr string, port int, timeout time.Duration) (Info, bool) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		return Info{}, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := "GET / HTTP/1.1\r\nHost: " + addr + "\r\nUser-Agent: netcrawler\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return Info{}, false
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return Info{}, false
	}
	defer resp.Body.Close()

	info := Info{HTTPServer: resp.Header.Get("Server")}
	body := make([]byte, 32*1024)
	n, _ := io.ReadFull(resp.Body, body)
	if m := titleRe.FindSubmatch(body[:n]); m != nil {
		info.HTTPTitle = strings.TrimSpace(strings.Join(strings.Fields(string(m[1])), " "))
	}
	if info.HTTPServer == "" && info.HTTPTitle == "" {
		return Info{}, false
	}
	return info, true
}

func probeBanner(ctx context.Context, addr string, port int, timeout time.Duration) (Info, bool) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		return Info{}, false
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n == 0 {
		return Info{}, false
	}
	banner := strings.TrimSpace(strings.ReplaceAll(string(buf[:n]), "\x00", ""))
	if banner == "" {
		return Info{}, false
	}
	return Info{Banner: banner}, true
}
