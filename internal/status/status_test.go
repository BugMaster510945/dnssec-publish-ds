package status

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")

	s1 := NewStore(path)
	s1.Set("g1/example.com", &ZoneState{
		InProgress: true,
		Raw: map[string]any{
			"task_id": "42",
			"status":  "todo",
		},
	})
	if err := s1.Save(); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	s2 := NewStore(path)
	s2.Load()
	st := s2.Get("g1/example.com")
	if st == nil {
		t.Fatalf("expected restored state")
	}
	if !st.InProgress {
		t.Fatalf("expected InProgress true, got %v", st.InProgress)
	}
	if st.Raw["task_id"] != "42" {
		t.Fatalf("expected task_id 42, got %#v", st.Raw)
	}
}

func TestStoreLoadCorruptedStartsFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")
	if err := os.WriteFile(path, []byte("{not-json"), 0644); err != nil {
		t.Fatalf("write corrupted file: %v", err)
	}

	s := NewStore(path)
	s.Load()
	if got := s.Get("g1/example.com"); got != nil {
		t.Fatalf("expected empty state after corrupted file load")
	}
}

func TestStorePruneRemovesUnknownZones(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "status.json")

	s := NewStore(path)
	s.Set("g1/example.com", &ZoneState{
		InProgress: true,
		Raw:        map[string]any{"task_id": "1"},
	})
	s.Set("g2/example.net", &ZoneState{
		InProgress: true,
		Raw:        map[string]any{"task_id": "2"},
	})

	s.Prune(map[string]bool{"g1/example.com": true})
	if s.Get("g1/example.com") == nil {
		t.Fatalf("expected kept zone to remain")
	}
	if s.Get("g2/example.net") != nil {
		t.Fatalf("expected unknown zone to be pruned")
	}
}
