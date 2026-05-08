package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

// Plugin is the global plugin object for one provider implementation.
// Implementations must be safe for concurrent use.
type Plugin interface {
	// Name returns the plugin identifier (e.g. "ovh-v1").
	Name() string

	// Capabilities returns what the plugin requires from the core.
	Capabilities() Capabilities

	// Init initialises plugin-global state from [plugins."<name>"] config.
	// Called once per used plugin type.
	Init(globalConfig map[string]any, logger *slog.Logger) error

	// NewGroup creates one group-specific plugin instance from
	// [group.<name>.plugin_config].
	NewGroup(groupName string, groupConfig map[string]any) (GroupPlugin, error)
}

// GroupPlugin is a group-specific instance created by a Plugin.
// It handles provider workflow for zones of that group.
type GroupPlugin interface {
	// Name returns the plugin identifier of this group instance.
	Name() string

	// Capabilities returns what this group instance requires from the core.
	Capabilities() Capabilities

	Update(ctx context.Context, req UpdateRequest) (UpdateResult, error)
}

// Factory is a function that creates a new plugin instance.
type Factory func() Plugin

var (
	registryMu sync.RWMutex
	registry   = make(map[string]Factory)
)

// Register adds a plugin factory to the global registry.
func Register(name string, factory Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = factory
}

// Get returns a new plugin instance from the registry.
func Get(name string) (Plugin, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	factory, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown plugin: %q", name)
	}
	return factory(), nil
}

// Available returns the names of all registered plugins.
func Available() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
