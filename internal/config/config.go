package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	Version     int         `json:"version"`
	Targets     Targets     `json:"targets"`
	Ports       Ports       `json:"ports"`
	Hostname    Hostname    `json:"hostname"`
	Performance Performance `json:"performance"`
	Output      Output      `json:"output"`
}

type Targets struct {
	Include []string `json:"include"`
	Deny    []string `json:"deny"`
}

type Ports struct {
	Enabled   bool  `json:"enabled"`
	Preset    string `json:"preset"`
	Custom    []int `json:"custom"`
	TimeoutMs int   `json:"timeoutMs"`
}

type Hostname struct {
	Enabled    bool `json:"enabled"`
	ReverseDNS bool `json:"reverseDns"`
	TimeoutMs  int  `json:"timeoutMs"`
}

type Performance struct {
	MaxConcurrentConnections int `json:"maxConcurrentConnections"`
}

type Output struct {
	Directory   string `json:"directory"`
	PrettyPrint bool   `json:"prettyPrint"`
}

func Load(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.Version != 1 {
		return nil, fmt.Errorf("unsupported config version: %d", cfg.Version)
	}
	if len(cfg.Targets.Include) == 0 {
		return nil, fmt.Errorf("no targets configured")
	}
	if cfg.Performance.MaxConcurrentConnections < 1 {
		cfg.Performance.MaxConcurrentConnections = 200
	}
	if cfg.Ports.TimeoutMs < 1 {
		cfg.Ports.TimeoutMs = 500
	}
	if cfg.Hostname.TimeoutMs < 1 {
		cfg.Hostname.TimeoutMs = 1000
	}
	if cfg.Output.Directory == "" {
		cfg.Output.Directory = "./results"
	}
	return &cfg, nil
}
