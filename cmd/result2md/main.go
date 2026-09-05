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

	"netcrawler/internal/envconfig"
	"netcrawler/internal/result"
)

func main() {
	if err := envconfig.Load(".env"); err != nil {
		log.Fatalf("load .env: %v", err)
	}
	input := flag.String("input", envconfig.Get("RESULTS", "./results"), "JSON result file or directory")
	output := flag.String("output", envconfig.Get("EXPORT", "./export"), "Markdown output file or directory")
	flag.Parse()
	if err := export(*input, *output); err != nil {
		log.Fatal(err)
	}
}

func export(input, output string) error {
	files, inputIsDir, err := resultFiles(input)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no JSON result files found in %s", input)
	}

	var scans []result.NetworkResult
	for _, filename := range files {
		scan, err := read(filename)
		if err != nil {
			return fmt.Errorf("read %s: %w", filename, err)
		}
		scans = append(scans, scan)
	}
	sort.Slice(scans, func(i, j int) bool { return result.CompareNetworks(scans[i].Network, scans[j].Network) < 0 })

	if inputIsDir {
		if err := ensureDirectoryOutput(output); err != nil {
			return err
		}
		for _, scan := range scans {
			filename := filepath.Join(output, networkName(scan.Network)+".md")
			if err := os.WriteFile(filename, []byte(render([]result.NetworkResult{scan})), 0644); err != nil {
				return err
			}
		}
		if err := os.WriteFile(filepath.Join(output, "all.md"), []byte(render(scans)), 0644); err != nil {
			return err
		}
		fmt.Printf("[INFO] Exported %d network(s) from %d JSON file(s) to %s\n", len(scans), len(files), output)
		return nil
	}

	target, err := singleFileOutput(output, networkName(scans[0].Network)+".md", ".md")
	if err != nil {
		return err
	}
	if err := os.WriteFile(target, []byte(render(scans)), 0644); err != nil {
		return err
	}
	fmt.Printf("[INFO] Exported 1 network to %s\n", target)
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

func read(filename string) (result.NetworkResult, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return result.NetworkResult{}, err
	}
	var scan result.NetworkResult
	if err := json.Unmarshal(data, &scan); err != nil {
		return result.NetworkResult{}, err
	}
	return scan, nil
}

func render(scans []result.NetworkResult) string {
	var b strings.Builder
	b.WriteString("# Net Crawler Scan Report\n\n")
	for _, scan := range scans {
		fmt.Fprintf(&b, "## %s\n\n- Scanned: %d\n- Denied: %d\n- Responsive: %d\n- Open ports: %d\n\n",
			scan.Network, scan.Statistics.Scanned, scan.Statistics.Denied, scan.Statistics.Responsive, scan.Statistics.OpenPorts)
		b.WriteString("| IP | Hostname | Ports |\n|---|---|---|\n")
		var ips []string
		for ip := range scan.Hosts {
			ips = append(ips, ip)
		}
		sort.Slice(ips, func(i, j int) bool { return result.CompareIPs(ips[i], ips[j]) < 0 })
		for _, ip := range ips {
			host := scan.Hosts[ip]
			ports := append([]int(nil), host.Ports...)
			sort.Ints(ports)
			var values []string
			for _, port := range ports {
				values = append(values, strconv.Itoa(port))
			}
			fmt.Fprintf(&b, "| %s | %s | %s |\n", escape(ip), escape(host.Hostname), escape(strings.Join(values, ", ")))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func networkName(network string) string { return strings.ReplaceAll(network, "/", "_") }
func escape(value string) string        { return strings.ReplaceAll(value, "|", `\|`) }
