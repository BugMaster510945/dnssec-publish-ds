package plugin

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewLimiterRejectsInvalidLimit(t *testing.T) {
	if _, err := NewLimiter(0); err == nil {
		t.Fatal("expected error for limit=0")
	}
}

func TestLimiterAcquireRelease(t *testing.T) {
	l, err := NewLimiter(1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := l.Acquire(context.Background()); err != nil {
		t.Fatalf("unexpected acquire error: %v", err)
	}
	l.Release()
}

func TestLimiterAcquireContextCancel(t *testing.T) {
	l, err := NewLimiter(1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := l.Acquire(context.Background()); err != nil {
		t.Fatalf("unexpected acquire error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = l.Acquire(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}

	l.Release()
}

func TestWithLimiterRunsFunction(t *testing.T) {
	l, err := NewLimiter(1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	called := false
	wait, err := WithLimiter(context.Background(), l, func() error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("expected function to be called")
	}
	if wait < 0 {
		t.Fatalf("expected non-negative wait, got %s", wait)
	}
}

func TestParseIntOptionDefault(t *testing.T) {
	v, err := ParseIntOption(map[string]any{}, "max_concurrency", 7)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 7 {
		t.Fatalf("expected default=7, got %d", v)
	}
}

func TestParseIntOptionString(t *testing.T) {
	v, err := ParseIntOption(map[string]any{"max_concurrency": "3"}, "max_concurrency", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 3 {
		t.Fatalf("expected 3, got %d", v)
	}
}

func TestParseIntOptionInvalidType(t *testing.T) {
	_, err := ParseIntOption(map[string]any{"max_concurrency": time.Second}, "max_concurrency", 1)
	if err == nil {
		t.Fatal("expected error for unsupported type")
	}
}
