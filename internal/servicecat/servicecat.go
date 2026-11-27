// Package servicecat sorts detected services into a few categories (web,
// remote access, file sharing, …) for grouped views and the export.
package servicecat

import "strings"

// Category IDs, in display order.
const (
	Web      = "web"
	Remote   = "remote"
	Files    = "files"
	Database = "database"
	Mail     = "mail"
	Network  = "network"
	Media    = "media"
	Printer  = "printer"
	Other    = "other"
)

// Order lists all categories in display order.
var Order = []string{Web, Remote, Files, Database, Mail, Network, Media, Printer, Other}

// Labels are the German display names.
var Labels = map[string]string{
	Web:      "Web",
	Remote:   "Fernzugriff",
	Files:    "Dateifreigabe",
	Database: "Datenbanken",
	Mail:     "Mail",
	Network:  "Netzdienste",
	Media:    "Medien & Smart Home",
	Printer:  "Drucker",
	Other:    "Sonstiges",
}

// byName maps service names (as nmap reports them, lower case) to a
// category.
var byName = map[string]string{}

func init() {
	for cat, names := range map[string][]string{
		Web: {"http", "https", "http-proxy", "http-alt", "https-alt", "http-mgmt", "webcache", "vnc-http", "upnp-http"},
		Remote: {"ssh", "telnet", "ms-wbt-server", "rdp", "vnc", "x11", "rlogin", "login", "shell", "exec",
			"wsman", "wsmans", "teamviewer", "anydesk", "nomachine", "nx"},
		Files: {"microsoft-ds", "netbios-ssn", "smb", "nfs", "nfsd", "mountd", "ftp", "ftps", "ftp-data", "afp",
			"afpovertcp", "rsync", "tftp", "webdav", "iscsi", "iscsi-target", "svn", "git"},
		Database: {"mysql", "postgresql", "ms-sql-s", "ms-sql-m", "oracle", "oracle-tns", "redis", "mongodb", "mongod",
			"memcached", "elasticsearch", "couchdb", "cassandra", "influxdb"},
		Mail: {"smtp", "smtps", "submission", "submissions", "imap", "imaps", "pop3", "pop3s", "lmtp", "sieve"},
		Network: {"domain", "dns", "ntp", "snmp", "ldap", "ldaps", "kerberos", "kerberos-sec", "kpasswd5", "upnp", "ssdp",
			"rpcbind", "msrpc", "epmap", "dhcp", "bgp", "ident", "pptp", "openvpn", "isakmp", "globalcatldap", "syslog",
			"zeroconf", "mdns", "llmnr", "tor-orport"},
		Media: {"rtsp", "mqtt", "secure-mqtt", "sip", "sip-tls", "daap", "airplay", "raop", "plex", "sonos",
			"spotify", "upnp-av", "dlna", "chromecast", "homekit", "hap"},
		Printer: {"ipp", "ipps", "printer", "jetdirect", "pdl-datastream", "lpd"},
	} {
		for _, n := range names {
			byName[n] = cat
		}
	}
}

// byPort is the fallback when the service name says nothing.
var byPort = map[int]string{
	80: Web, 443: Web, 8000: Web, 8008: Web, 8080: Web, 8081: Web, 8443: Web, 8888: Web,
	22: Remote, 23: Remote, 3389: Remote, 5900: Remote, 5901: Remote, 5985: Remote, 5986: Remote,
	21: Files, 139: Files, 445: Files, 548: Files, 873: Files, 2049: Files, 3260: Files,
	1433: Database, 1521: Database, 3306: Database, 5432: Database, 6379: Database, 9200: Database, 11211: Database, 27017: Database,
	25: Mail, 110: Mail, 143: Mail, 465: Mail, 587: Mail, 993: Mail, 995: Mail,
	53: Network, 88: Network, 111: Network, 123: Network, 135: Network, 161: Network, 389: Network, 636: Network, 1900: Network,
	554: Media, 1883: Media, 5060: Media, 8123: Media, 8883: Media, 32400: Media,
	515: Printer, 631: Printer, 9100: Printer,
}

// byProduct catches software whose protocol says little (e.g. a web UI
// that is really a media server or a smart home hub).
var byProduct = []struct{ substr, cat string }{
	{"plex", Media}, {"home assistant", Media}, {"jellyfin", Media}, {"emby", Media},
	{"sonos", Media}, {"homebridge", Media}, {"node-red", Media}, {"zigbee2mqtt", Media},
	{"cups", Printer},
}

// Of returns the category of a service: by product, then by service name,
// then by port; Other if nothing fits.
func Of(name, product string, port int) string {
	p := strings.ToLower(product)
	for _, b := range byProduct {
		if p != "" && strings.Contains(p, b.substr) {
			return b.cat
		}
	}
	n := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(name)), "ssl/")
	if c, ok := byName[n]; ok {
		return c
	}
	if c, ok := byPort[port]; ok && (n == "" || n == "unknown" || strings.HasSuffix(n, "?")) {
		return c
	}
	return Other
}
