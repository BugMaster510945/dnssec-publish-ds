package status

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const currentVersion = 1

// File represents the persisted state of the daemon.
type File struct {
	Version int                   `json:"version"`
	Zones   map[string]*ZoneState `json:"zones"`
}

// ZoneState holds the persisted state for a single zone.
// InProgress indicates if there is an operation being tracked.
// Raw holds provider-specific state (opaque, may include plugin's internal FSM).
type ZoneState struct {
	InProgress bool           `json:"in_progress"`
	Group      string         `json:"group,omitempty"`
	Plugin     string         `json:"plugin,omitempty"`
	Raw        map[string]any `json:"raw,omitempty"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// Store manages reading and writing of the status file.
type Store struct {
	path string
	mu   sync.Mutex
	data *File
}

// NewStore creates a store that persists to the given path.
func NewStore(path string) *Store {
	return &Store{
		path: path,
		data: &File{Version: currentVersion, Zones: make(map[string]*ZoneState)},
	}
}

// Load reads the status file from disk. If the file is absent, corrupted, or
// has an incompatible version, the store starts empty and logs a warning.
func (s *Store) Load() {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("status file unreadable, starting fresh", "path", s.path, "error", err)
		}
		return
	}

	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		slog.Warn("status file corrupted, starting fresh", "path", s.path, "error", err)
		return
	}

	if f.Version != currentVersion {
		slog.Warn("status file version mismatch, starting fresh",
			"path", s.path, "found", f.Version, "expected", currentVersion)
		return
	}

	if f.Zones == nil {
		f.Zones = make(map[string]*ZoneState)
	}

	s.data = &f
}

// Get returns the persisted state for a zone key (zone fqdn), or nil.
func (s *Store) Get(key string) *ZoneState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Zones[key]
}

// Set stores the state for a zone key.
func (s *Store) Set(key string, state *ZoneState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state.UpdatedAt = time.Now()
	s.data.Zones[key] = state
}

// Clear removes the state for a zone key (natural cleanup when operation
// completes).
func (s *Store) Clear(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data.Zones, key)
}

// Prune removes entries whose keys are not in the provided set of valid keys.
func (s *Store) Prune(validKeys map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.data.Zones {
		if !validKeys[k] {
			slog.Warn("pruning unknown zone from status", "key", k)
			delete(s.data.Zones, k)
		}
	}
}

// Save writes the status file to disk atomically.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating status directory: %w", err)
	}

	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling status: %w", err)
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0644); err != nil {
		return fmt.Errorf("writing temp status file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("renaming status file: %w", err)
	}

	return nil
}
