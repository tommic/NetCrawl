package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"netcrawler/internal/result"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

func main() {
	in := flag.String("input", "./results", "JSON result file or directory")
	out := flag.String("output", "./export", "Export directory")
	flag.Parse()
	fs, e := files(*in)
	if e != nil {
		log.Fatal(e)
	}
	os.MkdirAll(*out, 0755)
	var all []result.NetworkResult
	for _, f := range fs {
		b, e := os.ReadFile(f)
		if e != nil {
			log.Fatal(e)
		}
		var s result.NetworkResult
		if e = json.Unmarshal(b, &s); e != nil {
			log.Fatal(e)
		}
		all = append(all, s)
		if e = os.WriteFile(filepath.Join(*out, name(s.Network)+".md"), []byte(render([]result.NetworkResult{s})), 0644); e != nil {
			log.Fatal(e)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Network < all[j].Network })
	if e = os.WriteFile(filepath.Join(*out, "all.md"), []byte(render(all)), 0644); e != nil {
		log.Fatal(e)
	}
	fmt.Printf("[INFO] Exported %d network(s) to %s\n", len(all), *out)
}
func render(ss []result.NetworkResult) string {
	var b strings.Builder
	b.WriteString("# Net Crawler Scan Report\n\n")
	for _, s := range ss {
		fmt.Fprintf(&b, "## %s\n\n- Scanned: %d\n- Denied: %d\n- Responsive: %d\n- Open ports: %d\n\n| IP | Hostname | Ports |\n|---|---|---|\n", s.Network, s.Statistics.Scanned, s.Statistics.Denied, s.Statistics.Responsive, s.Statistics.OpenPorts)
		var ips []string
		for ip := range s.Hosts {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		for _, ip := range ips {
			h := s.Hosts[ip]
			sort.Ints(h.Ports)
			var ps []string
			for _, p := range h.Ports {
				ps = append(ps, strconv.Itoa(p))
			}
			fmt.Fprintf(&b, "| %s | %s | %s |\n", ip, h.Hostname, strings.Join(ps, ", "))
		}
		b.WriteString("\n")
	}
	return b.String()
}
func files(in string) ([]string, error) {
	i, e := os.Stat(in)
	if e != nil {
		return nil, e
	}
	if !i.IsDir() {
		return []string{in}, nil
	}
	var a []string
	e = filepath.WalkDir(in, func(p string, d fs.DirEntry, e error) error {
		if e == nil && !d.IsDir() && strings.ToLower(filepath.Ext(p)) == ".json" {
			a = append(a, p)
		}
		return e
	})
	sort.Strings(a)
	return a, e
}
func name(n string) string { return strings.ReplaceAll(n, "/", "_") }
