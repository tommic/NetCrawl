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

	"netcrawler/internal/envconfig"
	"netcrawler/internal/result"
)

type row struct {
	Network, IP, Hostname, Ports, Details string
}

func main() {
	if err := envconfig.Load(".env"); err != nil {
		log.Fatalf("load .env: %v", err)
	}

	input := flag.String("input", envconfig.Get("RESULTS", "./results"), "JSON result file or directory")
	output := flag.String("output", envconfig.Get("EXPORT", "./export"), "CSV output file or directory")
	flag.Parse()

	if err := export(*input, *output); err != nil {
		log.Fatal(err)
	}
}

// export accepts either one JSON file or a directory containing multiple result files.
func export(input, output string) error {
	files, inputIsDir, err := resultFiles(input)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no JSON result files found in %s", input)
	}

	scans := make([]struct {
		result result.NetworkResult
		rows   []row
	}, 0, len(files))
	var all []row

	for _, filename := range files {
		scan, rows, err := read(filename)
		if err != nil {
			return fmt.Errorf("read %s: %w", filename, err)
		}
		scans = append(scans, struct {
			result result.NetworkResult
			rows   []row
		}{scan, rows})
		all = append(all, rows...)
	}
	sortRows(all)

	if inputIsDir {
		if err := ensureDirectoryOutput(output); err != nil {
			return err
		}
		for _, scan := range scans {
			if err := writeCSV(filepath.Join(output, networkName(scan.result.Network)+".csv"), scan.rows); err != nil {
				return err
			}
		}
		if err := writeCSV(filepath.Join(output, "all.csv"), all); err != nil {
			return err
		}
		fmt.Printf("[INFO] Exported %d host(s) from %d JSON file(s) to %s\n", len(all), len(files), output)
		return nil
	}

	target, err := singleFileOutput(output, networkName(scans[0].result.Network)+".csv", ".csv")
	if err != nil {
		return err
	}
	if err := writeCSV(target, scans[0].rows); err != nil {
		return err
	}
	fmt.Printf("[INFO] Exported %d host(s) to %s\n", len(scans[0].rows), target)
	return nil
}

func resultFiles(input string) ([]string, bool, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, false, fmt.Errorf("input %q: %w", input, err)
	}
	if !info.IsDir() {
		if strings.ToLower(filepath.Ext(input)) != ".json" {
			return nil, false, fmt.Errorf("input file must have .json extension: %s", input)
		}
		return []string{input}, false, nil
	}

	var files []string
	err = filepath.WalkDir(input, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && strings.ToLower(filepath.Ext(path)) == ".json" {
			files = append(files, path)
		}
		return nil
	})
	sort.Strings(files)
	return files, true, err
}

func ensureDirectoryOutput(output string) error {
	if info, err := os.Stat(output); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("output must be a directory when input is a directory: %s", output)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if filepath.Ext(output) != "" {
		return fmt.Errorf("output looks like a file, but directory input requires an output directory: %s", output)
	}
	return os.MkdirAll(output, 0755)
}

func singleFileOutput(output, defaultName, extension string) (string, error) {
	if info, err := os.Stat(output); err == nil {
		if info.IsDir() {
			return filepath.Join(output, defaultName), nil
		}
		if strings.ToLower(filepath.Ext(output)) != extension {
			return "", fmt.Errorf("output file must have %s extension: %s", extension, output)
		}
		return output, nil
	} else if !os.IsNotExist(err) {
		return "", err
	}

	if strings.ToLower(filepath.Ext(output)) == extension {
		if dir := filepath.Dir(output); dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return "", err
			}
		}
		return output, nil
	}
	if filepath.Ext(output) != "" {
		return "", fmt.Errorf("output file must have %s extension: %s", extension, output)
	}
	if err := os.MkdirAll(output, 0755); err != nil {
		return "", err
	}
	return filepath.Join(output, defaultName), nil
}

func read(filename string) (result.NetworkResult, []row, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return result.NetworkResult{}, nil, err
	}
	var scan result.NetworkResult
	if err := json.Unmarshal(data, &scan); err != nil {
		return result.NetworkResult{}, nil, err
	}
	var rows []row
	for ip, host := range scan.Hosts {
		ports := append([]int(nil), host.Ports...)
		sort.Ints(ports)
		var values []string
		for _, port := range ports {
			values = append(values, strconv.Itoa(port))
		}
		rows = append(rows, row{scan.Network, ip, host.Hostname, strings.Join(values, ","), result.FormatDetails(host.Details, "; ")})
	}
	sortRows(rows)
	return scan, rows, nil
}

func sortRows(rows []row) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Network != rows[j].Network {
			return result.CompareNetworks(rows[i].Network, rows[j].Network) < 0
		}
		return result.CompareIPs(rows[i].IP, rows[j].IP) < 0
	})
}

func networkName(network string) string {
	return strings.ReplaceAll(network, "/", "_")
}

func writeCSV(filename string, rows []row) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	if err := writer.Write([]string{"network", "ip", "hostname", "ports", "details"}); err != nil {
		return err
	}
	for _, row := range rows {
		if err := writer.Write([]string{row.Network, row.IP, row.Hostname, row.Ports, row.Details}); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}
