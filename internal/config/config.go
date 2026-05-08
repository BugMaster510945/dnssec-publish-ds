package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config is the top-level application configuration.
type Config struct {
	StatusFile string                  `mapstructure:"status_file"    json:"status_file"`
	DNSTimeout time.Duration           `mapstructure:"dns_timeout"    json:"dns_timeout"`
	LogLevel   string                  `mapstructure:"log_level"      json:"log_level"`
	Groups     map[string]*GroupConfig `mapstructure:"group"          json:"groups"`
	// Plugins holds global, plugin-level configuration keyed by plugin name.
	// It is passed to plugins separately from group plugin_config.
	Plugins map[string]map[string]any `mapstructure:"plugins"        json:"plugins,omitempty"`
}

// GroupConfig defines a single group of zones managed by a plugin.
type GroupConfig struct {
	Plugin             string         `mapstructure:"plugin"              json:"plugin"`
	CheckInterval      time.Duration  `mapstructure:"check_interval"      json:"check_interval"`
	ErrorRetryInterval time.Duration  `mapstructure:"error_retry_interval" json:"error_retry_interval"`
	Zones              []string       `mapstructure:"zones"               json:"zones"`
	PluginConfig       map[string]any `mapstructure:"plugin_config"       json:"plugin_config"`
}

// Load reads the main configuration file and merges any files found in the
// conf.d directory next to it. Files in conf.d are loaded in lexicographic
// order. Environment variables with the DNSSEC_PUBLISH_DS_ prefix can
// override values.
func Load(path string) (*Config, error) {
	v := viper.New()

	// Defaults
	v.SetDefault("status_file", "/var/lib/dnssec-publish-ds/status.json")
	v.SetDefault("dns_timeout", "5s")
	v.SetDefault("log_level", "info")

	v.SetConfigFile(path)
	v.SetConfigType("toml")

	// Environment variable overrides
	v.SetEnvPrefix("DNSSEC_PUBLISH_DS")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	// Merge conf.d files
	confDir := filepath.Join(filepath.Dir(path), "conf.d")
	if err := mergeConfD(v, confDir); err != nil {
		return nil, fmt.Errorf("loading conf.d: %w", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Apply defaults to groups and set missing names
	for name, g := range cfg.Groups {
		if g == nil {
			g = &GroupConfig{}
			cfg.Groups[name] = g
		}
		if g.CheckInterval == 0 {
			g.CheckInterval = 12 * time.Hour
		}
		if g.ErrorRetryInterval == 0 {
			g.ErrorRetryInterval = 5 * time.Minute
		}
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// mergeConfD reads all .toml files from dir in lexicographic order and merges
// them into v.
func mergeConfD(v *viper.Viper, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading %s: %w", dir, err)
	}

	// Sort lexicographically (os.ReadDir already does, but be explicit)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("opening %s: %w", e.Name(), err)
		}
		if err := v.MergeConfig(f); err != nil {
			f.Close()
			return fmt.Errorf("merging %s: %w", e.Name(), err)
		}
		f.Close()
	}

	return nil
}

// validate checks configuration consistency.
func validate(cfg *Config) error {
	if cfg.StatusFile == "" {
		return fmt.Errorf("status_file must not be empty")
	}
	if cfg.DNSTimeout <= 0 {
		return fmt.Errorf("dns_timeout must be greater than zero")
	}
	if cfg.LogLevel == "" {
		return fmt.Errorf("log_level must not be empty")
	}
	switch strings.ToLower(cfg.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log_level must be one of: debug, info, warn, error")
	}

	if len(cfg.Groups) == 0 {
		return fmt.Errorf("no groups defined in configuration")
	}

	seenZones := make(map[string]string) // zone -> group name
	for name, g := range cfg.Groups {
		if g == nil {
			return fmt.Errorf("group %q is nil", name)
		}
		if name == "" {
			return fmt.Errorf("group with empty name")
		}
		if g.Plugin == "" {
			return fmt.Errorf("group %q: plugin not specified", name)
		}
		if g.CheckInterval <= 0 {
			return fmt.Errorf("group %q: check_interval must be greater than zero", name)
		}
		if len(g.Zones) == 0 {
			return fmt.Errorf("group %q: no zones defined", name)
		}
		if g.PluginConfig == nil {
			return fmt.Errorf("group %q: plugin_config must be set", name)
		}
		for _, z := range g.Zones {
			if strings.TrimSpace(z) == "" {
				return fmt.Errorf("group %q: zone must not be empty", name)
			}
			if prev, ok := seenZones[z]; ok {
				return fmt.Errorf("zone %q defined in both group %q and %q", z, prev, name)
			}
			seenZones[z] = name
		}
	}

	return nil
}
