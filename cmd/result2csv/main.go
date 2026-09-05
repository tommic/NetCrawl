package main

import (
	"encoding/csv"
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

type row struct{ Network, IP, Hostname, Ports string }

func main() {
	in := flag.String("input", "./results", "JSON result file or directory")
	out := flag.String("output", "./export", "Export directory")
	flag.Parse()
	files, e := files(*in)
	if e != nil {
		log.Fatal(e)
	}
	os.MkdirAll(*out, 0755)
	var all []row
	for _, f := range files {
		data, e := os.ReadFile(f)
		if e != nil {
			log.Fatal(e)
		}
		var s result.NetworkResult
		if e = json.Unmarshal(data, &s); e != nil {
			log.Fatal(e)
		}
		var rr []row
		for ip, h := range s.Hosts {
			sort.Ints(h.Ports)
			var ps []string
			for _, p := range h.Ports {
				ps = append(ps, strconv.Itoa(p))
			}
			rr = append(rr, row{s.Network, ip, h.Hostname, strings.Join(ps, ",")})
		}
		sortRows(rr)
		all = append(all, rr...)
		if e = write(filepath.Join(*out, name(s.Network)+".csv"), rr); e != nil {
			log.Fatal(e)
		}
	}
	sortRows(all)
	if e = write(filepath.Join(*out, "all.csv"), all); e != nil {
		log.Fatal(e)
	}
	fmt.Printf("[INFO] Exported %d host(s) to %s\n", len(all), *out)
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
func sortRows(a []row) {
	sort.Slice(a, func(i, j int) bool {
		if a[i].Network != a[j].Network {
			return a[i].Network < a[j].Network
		}
		return a[i].IP < a[j].IP
	})
}
func name(n string) string { return strings.ReplaceAll(n, "/", "_") }
func write(f string, a []row) error {
	x, e := os.Create(f)
	if e != nil {
		return e
	}
	defer x.Close()
	w := csv.NewWriter(x)
	_ = w.Write([]string{"network", "ip", "hostname", "ports"})
	for _, r := range a {
		_ = w.Write([]string{r.Network, r.IP, r.Hostname, r.Ports})
	}
	w.Flush()
	return w.Error()
}
