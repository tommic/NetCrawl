package main

import (
	"encoding/csv"
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

// csvRow represents one open port in the CSV export.
type csvRow struct {
	Network  string
	IP       string
	Hostname string
	Ports    string
}

// main exports Net Crawler JSON result files to CSV.
func main() {
	input := flag.String("input", "./results", "JSON result file or directory")
	output := flag.String("output", "./results.csv", "CSV output file")
	flag.Parse()

	files, err := resultFiles(*input)
	if err != nil {
		log.Fatalf("input: %v", err)
	}

	rows := make([]csvRow, 0)

	for _, filename := range files {
		resultRows, err := readResult(filename)
		if err != nil {
			log.Fatalf("read %s: %v", filename, err)
		}
		rows = append(rows, resultRows...)
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Network != rows[j].Network {
			return rows[i].Network < rows[j].Network
		}
		if rows[i].IP != rows[j].IP {
			return rows[i].IP < rows[j].IP
		}
		return rows[i].IP < rows[j].IP
	})

	if err := writeCSV(*output, rows); err != nil {
		log.Fatalf("write CSV: %v", err)
	}

	fmt.Printf("[INFO] Exported %d row(s) from %d JSON file(s) to %s\n", len(rows), len(files), *output)
}

// resultFiles returns JSON result files from a file or directory.
func resultFiles(input string) ([]string, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		if strings.ToLower(filepath.Ext(input)) != ".json" {
			return nil, fmt.Errorf("input file must be JSON")
		}
		return []string{input}, nil
	}

	files := make([]string, 0)

	err = filepath.WalkDir(input, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) == ".json" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Strings(files)
	return files, nil
}

// readResult reads one crawler JSON result and converts it to CSV rows.
func readResult(filename string) ([]csvRow, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var scan result.NetworkResult
	if err := json.Unmarshal(data, &scan); err != nil {
		return nil, err
	}

	rows := make([]csvRow, 0)

	for ip, host := range scan.Hosts {
		ports := make([]string, 0, len(host.Ports))
		for _, port := range host.Ports { ports = append(ports, strconv.Itoa(port)) }
		rows = append(rows, csvRow{Network: scan.Network, IP: ip, Hostname: host.Hostname, Ports: strings.Join(ports, ",")})
	}

	return rows, nil
}

// writeCSV writes all exported rows to a CSV file.
func writeCSV(filename string, rows []csvRow) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"network", "ip", "hostname", "ports"}); err != nil {
		return err
	}

	for _, row := range rows {
		if err := writer.Write([]string{
			row.Network,
			row.IP,
			row.Hostname,
			row.Ports,
		}); err != nil {
			return err
		}
	}

	writer.Flush()
	return writer.Error()
}
