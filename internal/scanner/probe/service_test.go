package probe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestMatchGreeting(t *testing.T) {
	cases := []struct {
		in                     string
		name, product, version string
	}{
		{"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", "ssh", "OpenSSH", "9.6p1"},
		{"SSH-2.0-dropbear_2022.83\r\n", "ssh", "Dropbear", "2022.83"},
		{"SSH-2.0-RomSShell_5.40\r\n", "ssh", "RomSShell", "5.40"},
		{"220 ProFTPD 1.3.8 Server (Debian) [::ffff:10.0.0.2]\r\n", "ftp", "ProFTPD", "1.3.8"},
		{"220 (vsFTPd 3.0.5)\r\n", "ftp", "vsftpd", "3.0.5"},
		{"220 mail.example.org ESMTP Postfix (Debian/GNU)\r\n", "smtp", "Postfix", ""},
		{"220 mx ESMTP Exim 4.96 Mon, 27 Nov 2026\r\n", "smtp", "Exim", "4.96"},
		{"220 FRITZ!Box SMTP ready\r\n", "smtp", "", ""},
		{"+OK Dovecot ready.\r\n", "pop3", "Dovecot", ""},
		{"* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n", "imap", "Dovecot", ""},
		{"hello there\r\n", "unknown", "", ""},
	}
	for _, c := range cases {
		s, ok := matchGreeting([]byte(c.in))
		if !ok || s.Name != c.name || s.Product != c.product || s.Version != c.version {
			t.Errorf("%q: %+v", c.in, s)
		}
	}
	if s, _ := matchGreeting([]byte("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")); s.Extra != "Ubuntu-3ubuntu13" {
		t.Errorf("extra = %q", s.Extra)
	}
}

func TestMySQLGreeting(t *testing.T) {
	pkt := func(v string) []byte {
		b := []byte{0, 0, 0, 0, 0x0a}
		return append(append(b, v...), 0, 1, 2, 3)
	}
	if s, ok := matchGreeting(pkt("8.0.36")); !ok || s.Name != "mysql" || s.Product != "MySQL" || s.Version != "8.0.36" {
		t.Errorf("mysql: %+v", s)
	}
	if s, _ := matchGreeting(pkt("5.5.5-10.11.6-MariaDB-0+deb12u1")); s.Product != "MariaDB" || s.Version != "10.11.6" {
		t.Errorf("mariadb: %+v", s)
	}
}

func TestParseServerHeader(t *testing.T) {
	cases := map[string]Service{
		"nginx/1.24.0 (Ubuntu)": {Product: "nginx", Version: "1.24.0", Extra: "Ubuntu"},
		"Apache/2.4.58":         {Product: "Apache", Version: "2.4.58"},
		"Microsoft-IIS/10.0":    {Product: "Microsoft-IIS", Version: "10.0"},
		"lighttpd":              {Product: "lighttpd"},
		"":                      {},
	}
	for in, want := range cases {
		if got := parseServerHeader(in); got != want {
			t.Errorf("%q: %+v, want %+v", in, got, want)
		}
	}
}

func TestParseNmapXML(t *testing.T) {
	xml := `<?xml version="1.0"?><nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6p1 Ubuntu 3ubuntu13" extrainfo="Ubuntu Linux; protocol 2.0"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="http" product="nginx" version="1.24.0" tunnel="ssl"/></port>
<port protocol="tcp" portid="81"><state state="closed"/><service name="hosts2-ns"/></port>
</ports></host></nmaprun>`
	got := parseNmapXML([]byte(xml))
	if s := got[22]; s.Name != "ssh" || s.Product != "OpenSSH" || s.Version != "9.6p1 Ubuntu 3ubuntu13" || s.Method != "nmap" {
		t.Errorf("22: %+v", s)
	}
	if s := got[443]; s.Name != "https" || s.Product != "nginx" {
		t.Errorf("443: %+v", s)
	}
	if _, ok := got[81]; ok {
		t.Error("closed port must be skipped")
	}
	if parseNmapXML([]byte("garbage")) != nil {
		t.Error("bad XML must give nothing")
	}
}

func TestNmapArgs(t *testing.T) {
	got := fmt.Sprint(nmapArgs("10.0.0.5", []int{22, 80}))
	if got != "[-sV -Pn -n --unprivileged --version-intensity 5 --host-timeout 180s -p 22,80 -oX - -- 10.0.0.5]" {
		t.Errorf("args = %s", got)
	}
}

// Built-in detection against local servers: a greeting, plain HTTP and
// HTTPS; a silent port is not reported.
func TestServicesBuiltin(t *testing.T) {
	greet := listen(t, func(c net.Conn) { fmt.Fprint(c, "SSH-2.0-OpenSSH_9.6p1 Debian-4\r\n"); time.Sleep(time.Second) })
	web := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0 (Ubuntu)")
	}))
	defer web.Close()
	tlsWeb := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Caddy")
	}))
	defer tlsWeb.Close()
	silent := listen(t, func(c net.Conn) { buf := make([]byte, 64); _, _ = c.Read(buf) })

	hosts := map[string][]int{"127.0.0.1": {greet, portOf(t, web.URL), portOf(t, tlsWeb.URL), silent}}
	got := Services(context.Background(), hosts, "", 500*time.Millisecond, 4)["127.0.0.1"]
	if s := got[greet]; s.Name != "ssh" || s.Product != "OpenSSH" || s.Version != "9.6p1" || s.Method != "banner" {
		t.Errorf("ssh: %+v", s)
	}
	if s := got[portOf(t, web.URL)]; s.Name != "http" || s.Product != "nginx" || s.Version != "1.24.0" {
		t.Errorf("http: %+v", s)
	}
	if s := got[portOf(t, tlsWeb.URL)]; s.Name != "https" || s.Product != "Caddy" {
		t.Errorf("https: %+v", s)
	}
	if s, ok := got[silent]; ok {
		t.Errorf("silent port: %+v", s)
	}
}

func listen(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func portOf(t *testing.T, raw string) int {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("port of %s: %v", raw, err)
	}
	return n
}
