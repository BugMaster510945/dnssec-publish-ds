package ovhv1

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/plugin"
)

func TestInitGlobalSetsMaxConcurrency(t *testing.T) {
	p := &OVHv1Plugin{}
	if err := p.Init(
		map[string]any{"max_concurrency": 3},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.throttle == nil {
		t.Fatal("expected limiter to be initialized")
	}
	if p.throttle.Limit() != 3 {
		t.Fatalf("expected limiter limit=3, got %d", p.throttle.Limit())
	}
}

func TestNewGroupRejectsGroupLevelMaxConcurrency(t *testing.T) {
	p := &OVHv1Plugin{}
	if err := p.Init(map[string]any{}, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatalf("unexpected init error: %v", err)
	}

	_, err := p.NewGroup(
		"ovh-main",
		map[string]any{"max_concurrency": 2},
	)
	if err == nil {
		t.Fatal("expected error for group-level max_concurrency")
	}
	if !strings.Contains(err.Error(), "[plugins.\"ovh-v1\"]") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildDesiredKeysNoChange(t *testing.T) {
	current := map[int]ovhKey{
		10: {
			ID:        10,
			Tag:       12345,
			Algorithm: 13,
			Flags:     257,
			PublicKey: "aaa",
			Status:    "ok",
		},
		11: {
			ID:        11,
			Tag:       54321,
			Algorithm: 13,
			Flags:     257,
			PublicKey: "bbb",
			Status:    "expired",
		},
	}

	flags := uint16(257)
	pubA := "aaa"
	pubB := "bbb"

	req := plugin.UpdateRequest{
		ToAdd: []plugin.KeyRecord{
			{Tag: 54321, Algorithm: 13, Flags: &flags, PublicKey: &pubB},
			{Tag: 12345, Algorithm: 13, Flags: &flags, PublicKey: &pubA},
		},
	}

	desired, added, removed := buildDesiredKeys(current, req)
	if len(desired) != 2 {
		t.Fatalf("expected 2 desired keys, got %d", len(desired))
	}
	if added != 0 || removed != 0 {
		t.Fatalf("expected no real change, got added=%d removed=%d", added, removed)
	}
}

func TestBuildDesiredKeysDetectsChanges(t *testing.T) {
	current := map[int]ovhKey{
		10: {
			ID:        10,
			Tag:       12345,
			Algorithm: 13,
			Flags:     257,
			PublicKey: "aaa",
		},
	}

	flags := uint16(257)
	pubNew := "different"

	req := plugin.UpdateRequest{
		ToRemove: []plugin.KeyRecord{{Tag: 12345, Algorithm: 13}},
		ToAdd:    []plugin.KeyRecord{{Tag: 12345, Algorithm: 13, Flags: &flags, PublicKey: &pubNew}},
	}

	desired, added, removed := buildDesiredKeys(current, req)
	if len(desired) != 1 {
		t.Fatalf("expected 1 desired key, got %d", len(desired))
	}
	if added != 1 || removed != 1 {
		t.Fatalf("expected added=1 removed=1, got added=%d removed=%d", added, removed)
	}
}
