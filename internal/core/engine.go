package core

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/config"
	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/plugin"
	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/status"

	// Register plugins
	_ "gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/plugin/ovhv1"
)

// Engine is the main daemon controller.
type Engine struct {
	cfg               *config.Config
	cfgPath           string
	skipInitialJitter bool
}

// NewEngine creates a new engine from the given configuration.
func NewEngine(cfg *config.Config, cfgPath string, skipInitialJitter bool) *Engine {
	return &Engine{cfg: cfg, cfgPath: cfgPath, skipInitialJitter: skipInitialJitter}
}

// Run starts the daemon. It blocks until a termination signal is received.
// SIGHUP triggers a full config reload (treated as a logical restart).
func (e *Engine) Run() error {
	for {
		restart, err := e.runOnce()
		if err != nil {
			return err
		}
		if !restart {
			return nil
		}
		slog.Info("reloading configuration")
	}
}

// runOnce runs the daemon until it's asked to stop or restart. Returns true
// if a restart (SIGHUP) was requested.
func (e *Engine) runOnce() (bool, error) {
	dns, err := NewDNSClient(e.cfg.DNSTimeout)
	if err != nil {
		return false, fmt.Errorf("initializing DNS client: %w", err)
	}

	store := status.NewStore(e.cfg.StatusFile)
	store.Load()

	// Build valid keys set and prune stale entries
	validKeys := make(map[string]bool)
	for _, g := range e.cfg.Groups {
		for _, z := range g.Zones {
			validKeys[z] = true
		}
	}
	store.Prune(validKeys)

	// Initialize one global plugin object per used plugin type.
	pluginGlobals := make(map[string]plugin.Plugin)
	for groupName, g := range e.cfg.Groups {
		if _, ok := pluginGlobals[g.Plugin]; ok {
			continue
		}
		p, err := plugin.Get(g.Plugin)
		if err != nil {
			return false, fmt.Errorf("group %q: %w", groupName, err)
		}
		if err := p.Init(e.cfg.Plugins[g.Plugin], slog.With("plugin", g.Plugin)); err != nil {
			return false, fmt.Errorf("group %q: initializing global plugin %q: %w", groupName, g.Plugin, err)
		}
		pluginGlobals[g.Plugin] = p
		slog.Info("initialized global plugin", "plugin", g.Plugin)
	}

	// Initialize one group plugin instance per group.
	groupPlugins := make(map[string]plugin.GroupPlugin)
	for name, g := range e.cfg.Groups {
		p := pluginGlobals[g.Plugin]
		gp, err := p.NewGroup(name, g.PluginConfig)
		if err != nil {
			return false, fmt.Errorf("group %q: initializing group plugin %q: %w", name, g.Plugin, err)
		}
		groupPlugins[name] = gp
		slog.Info("initialized group plugin instance", "group", name, "plugin", g.Plugin)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Launch one goroutine per zone
	var wg sync.WaitGroup
	for name, g := range e.cfg.Groups {
		gp := groupPlugins[name]
		for _, z := range g.Zones {
			wg.Add(1)
			runner := NewZoneRunner(name, z, g.CheckInterval, g.ErrorRetryInterval, gp, dns, store, e.skipInitialJitter)
			go func() {
				defer wg.Done()
				runner.Run(ctx)
			}()
		}
	}

	slog.Info("daemon started", "groups", len(e.cfg.Groups), "zones", len(validKeys))

	// Wait for signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)

	sig := <-sigCh
	signal.Stop(sigCh)

	slog.Info("received signal", "signal", sig)

	// Cancel all zone goroutines
	cancel()
	wg.Wait()

	// Save status before exiting
	if err := store.Save(); err != nil {
		slog.Error("failed to save status on shutdown", "error", err)
	}

	if sig == syscall.SIGHUP {
		// Reload configuration
		newCfg, err := config.Load(e.cfgPath)
		if err != nil {
			slog.Error("failed to reload configuration, shutting down", "error", err)
			return false, fmt.Errorf("config reload failed: %w", err)
		}
		e.cfg = newCfg
		slog.Info("configuration reloaded")
		return true, nil
	}

	slog.Info("shutting down", "signal", sig)
	return false, nil
}
