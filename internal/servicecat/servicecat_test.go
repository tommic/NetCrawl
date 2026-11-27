package servicecat

import "testing"

func TestOf(t *testing.T) {
	cases := []struct {
		name, product string
		port          int
		want          string
	}{
		{"http", "nginx", 80, Web},
		{"https", "", 443, Web},
		{"ssl/http", "", 8443, Web},
		{"ssh", "OpenSSH", 22, Remote},
		{"ms-wbt-server", "", 3389, Remote},
		{"microsoft-ds", "Samba smbd", 445, Files},
		{"mysql", "MariaDB", 3306, Database},
		{"smtp", "Postfix", 25, Mail},
		{"domain", "dnsmasq", 53, Network},
		{"rtsp", "", 554, Media},
		{"ipp", "CUPS", 631, Printer},
		{"jetdirect", "", 9100, Printer},
		{"http", "Plex Media Server httpd", 32400, Media}, // product wins
		{"http", "Home Assistant", 8123, Media},           // product wins
		{"unknown", "", 3306, Database},                   // port fallback
		{"", "", 22, Remote},                              // port fallback
		{"tcpwrapped", "", 22, Other},                     // named, but not a known protocol
		{"unknown", "", 40000, Other},                     // nothing fits
		{"SSH", "", 2222, Remote},                         // case-insensitive
	}
	for _, c := range cases {
		if got := Of(c.name, c.product, c.port); got != c.want {
			t.Errorf("Of(%q, %q, %d) = %s, want %s", c.name, c.product, c.port, got, c.want)
		}
	}
	for _, c := range Order {
		if Labels[c] == "" {
			t.Errorf("category %s has no label", c)
		}
	}
}
