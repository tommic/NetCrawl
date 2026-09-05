package result

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Host struct {
	Hostname string `json:"hostname,omitempty"`
	Ports    []int  `json:"ports"`
}

type NetworkResult struct {
	SchemaVersion int             `json:"schemaVersion"`
	Network       string          `json:"network"`
	Hosts         map[string]Host `json:"hosts"`
	Statistics    Statistics      `json:"statistics"`
}

type Statistics struct {
	Scanned    int `json:"scanned"`
	Denied     int `json:"denied"`
	Responsive int `json:"responsive"`
	OpenPorts  int `json:"openPorts"`
}

func Write(dir string, r NetworkResult, pretty bool) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	var data []byte
	var err error
	if pretty {
		data, err = json.MarshalIndent(r, "", "  ")
	} else {
		data, err = json.Marshal(r)
	}
	if err != nil {
		return err
	}
	name := strings.ReplaceAll(r.Network, "/", "_") + ".json"
	tmp := filepath.Join(dir, "."+name+".tmp")
	final := filepath.Join(dir, name)
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		return err
	}
	fmt.Printf("[INFO] Written %s\n", final)
	return nil
}
