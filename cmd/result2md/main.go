package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"netcrawler/internal/result"
)

// main exports Net Crawler JSON result files to a Markdown report.
func main() {
	input := flag.String("input", "./results", "JSON result file or directory")
	output := flag.String("output", "./results.md", "Markdown output file")
	flag.Parse()

	files, err := resultFiles(*input)
	if err != nil { log.Fatalf("input: %v", err) }

	var scans []result.NetworkResult
	for _, filename := range files {
		data, err := os.ReadFile(filename)
		if err != nil { log.Fatalf("read %s: %v", filename, err) }
		var scan result.NetworkResult
		if err := json.Unmarshal(data, &scan); err != nil { log.Fatalf("parse %s: %v", filename, err) }
		scans = append(scans, scan)
	}

	sort.Slice(scans, func(i, j int) bool { return scans[i].Network < scans[j].Network })

	var b strings.Builder
	b.WriteString("# Net Crawler Scan Report\n\n")
	for _, scan := range scans {
		fmt.Fprintf(&b, "## %s\n\n", scan.Network)
		fmt.Fprintf(&b, "- Scanned: %d\n- Denied: %d\n- Responsive: %d\n- Open ports: %d\n\n",
			scan.Statistics.Scanned, scan.Statistics.Denied, scan.Statistics.Responsive, scan.Statistics.OpenPorts)
		b.WriteString("| IP | Hostname | Ports |\n|---|---|---|\n")

		ips := make([]string, 0, len(scan.Hosts))
		for ip := range scan.Hosts { ips = append(ips, ip) }
		sort.Strings(ips)

		for _, ip := range ips {
			host := scan.Hosts[ip]
			ports := append([]int(nil), host.Ports...)
			sort.Ints(ports)
			values := make([]string, 0, len(ports))
			for _, port := range ports { values = append(values, strconv.Itoa(port)) }
			fmt.Fprintf(&b, "| %s | %s | %s |\n",
				escape(ip), escape(host.Hostname), escape(strings.Join(values, ", ")))
		}
		b.WriteString("\n")
	}

	if err := os.WriteFile(*output, []byte(b.String()), 0644); err != nil { log.Fatalf("write: %v", err) }
	fmt.Printf("[INFO] Exported %d network(s) to %s\n", len(scans), *output)
}

// resultFiles returns JSON result files from a file or directory.
func resultFiles(input string) ([]string, error) {
	info, err := os.Stat(input)
	if err != nil { return nil, err }
	if !info.IsDir() {
		if strings.ToLower(filepath.Ext(input)) != ".json" { return nil, fmt.Errorf("input file must be JSON") }
		return []string{input}, nil
	}
	var files []string
	err = filepath.WalkDir(input, func(path string, entry fs.DirEntry, err error) error {
		if err != nil { return err }
		if !entry.IsDir() && strings.ToLower(filepath.Ext(path)) == ".json" { files = append(files, path) }
		return nil
	})
	sort.Strings(files)
	return files, err
}

// escape protects Markdown table cells.
func escape(value string) string {
	return strings.ReplaceAll(value, "|", `\|`)
}
