package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateRejectsInvalidGlobalFields(t *testing.T) {
	base := Config{
		StatusFile: "/tmp/status.json",
		DNSTimeout: 5 * time.Second,
		LogLevel:   "info",
		Groups: map[string]*GroupConfig{
			"g1": {
				Plugin:        "ovh-v1",
				CheckInterval: 12 * time.Hour,
				Zones:         []string{"example.com"},
				PluginConfig:  map[string]any{"application_key": "x"},
			},
		},
	}

	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{
			name: "empty status file",
			mut: func(c *Config) {
				c.StatusFile = ""
			},
		},
		{
			name: "zero dns timeout",
			mut: func(c *Config) {
				c.DNSTimeout = 0
			},
		},
		{
			name: "invalid log level",
			mut: func(c *Config) {
				c.LogLevel = "trace"
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mut(&cfg)
			if err := validate(&cfg); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestValidateRejectsGroupIssues(t *testing.T) {
	cfg := Config{
		StatusFile: "/tmp/status.json",
		DNSTimeout: 5 * time.Second,
		LogLevel:   "info",
		Groups: map[string]*GroupConfig{
			"g1": {
				Plugin:        "ovh-v1",
				CheckInterval: 12 * time.Hour,
				Zones:         []string{"example.com"},
				PluginConfig:  map[string]any{"application_key": "x"},
			},
			"g2": {
				Plugin:        "ovh-v1",
				CheckInterval: 12 * time.Hour,
				Zones:         []string{"example.com"},
				PluginConfig:  map[string]any{"application_key": "y"},
			},
		},
	}

	// Duplicate zone in different groups should fail
	if err := validate(&cfg); err == nil {
		t.Fatalf("expected duplicate zone validation error")
	}

	// Fix the zone conflict
	cfg.Groups["g2"].Zones = []string{"example.net"}
	if err := validate(&cfg); err != nil {
		t.Fatalf("config should be valid after fixing zone conflict: %v", err)
	}

	// Missing plugin_config should fail
	cfg.Groups["g2"].PluginConfig = nil
	if err := validate(&cfg); err == nil {
		t.Fatalf("expected missing plugin_config validation error")
	}
}

func TestValidateAcceptsMinimalValidConfig(t *testing.T) {
	cfg := Config{
		StatusFile: "/tmp/status.json",
		DNSTimeout: 5 * time.Second,
		LogLevel:   "warn",
		Groups: map[string]*GroupConfig{
			"g1": {
				Plugin:        "ovh-v1",
				CheckInterval: 12 * time.Hour,
				Zones:         []string{"example.com"},
				PluginConfig: map[string]any{
					"endpoint":           "ovh-eu",
					"application_key":    "k",
					"application_secret": "s",
					"consumer_key":       "c",
				},
			},
		},
	}

	if err := validate(&cfg); err != nil {
		t.Fatalf("expected config to be valid, got error: %v", err)
	}
}

func TestLoadConfDOrderLastFileWins(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "conf.d")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		t.Fatalf("mkdir conf.d: %v", err)
	}

	mainCfg := `
status_file = "/tmp/status.json"
dns_timeout = "5s"
log_level = "info"

[group.g1]
plugin = "ovh-v1"
check_interval = "12h"
zones = ["example.com"]

[group.g1.plugin_config]
application_key = "k"
application_secret = "s"
consumer_key = "c"
`

	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(mainCfg), 0644); err != nil {
		t.Fatalf("write main config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "10-log.toml"), []byte("log_level = \"warn\"\n"), 0644); err != nil {
		t.Fatalf("write conf 10: %v", err)
	}
	if err := os.WriteFile(filepath.Join(confDir, "20-log.toml"), []byte("log_level = \"debug\"\n"), 0644); err != nil {
		t.Fatalf("write conf 20: %v", err)
	}

	cfg, err := Load(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("expected log_level debug from last conf.d file, got %q", cfg.LogLevel)
	}
}

func TestLoadEnvOverride(t *testing.T) {
	dir := t.TempDir()

	mainCfg := `
status_file = "/tmp/status.json"
dns_timeout = "5s"
log_level = "info"

[group.g1]
plugin = "ovh-v1"
check_interval = "12h"
zones = ["example.com"]

[group.g1.plugin_config]
application_key = "k"
application_secret = "s"
consumer_key = "c"
`

	confPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(confPath, []byte(mainCfg), 0644); err != nil {
		t.Fatalf("write main config: %v", err)
	}

	t.Setenv("DNSSEC_PUBLISH_DS_LOG_LEVEL", "error")

	cfg, err := Load(confPath)
	if err != nil {
		t.Fatalf("load config with env override: %v", err)
	}
	if cfg.LogLevel != "error" {
		t.Fatalf("expected env override log_level=error, got %q", cfg.LogLevel)
	}
}
