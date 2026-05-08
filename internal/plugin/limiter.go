package plugin

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

// Limiter bounds concurrent operations.
type Limiter struct {
	limit int
	sem   chan struct{}
}

// NewLimiter creates a concurrency limiter with the given maximum number of
// concurrent operations.
func NewLimiter(limit int) (*Limiter, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit must be greater than zero")
	}

	return &Limiter{
		limit: limit,
		sem:   make(chan struct{}, limit),
	}, nil
}

// Acquire waits for an execution slot and returns how long it waited.
func (l *Limiter) Acquire(ctx context.Context) (time.Duration, error) {
	if l == nil {
		return 0, fmt.Errorf("nil limiter")
	}

	start := time.Now()
	select {
	case l.sem <- struct{}{}:
		return time.Since(start), nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// Release frees one execution slot.
func (l *Limiter) Release() {
	if l == nil {
		return
	}
	<-l.sem
}

// Limit returns the configured maximum concurrency.
func (l *Limiter) Limit() int {
	if l == nil {
		return 0
	}
	return l.limit
}

// WithLimiter runs fn while holding one limiter slot and returns the wait time
// before the slot was acquired.
func WithLimiter(ctx context.Context, limiter *Limiter, fn func() error) (time.Duration, error) {
	if limiter == nil {
		return 0, fmt.Errorf("nil limiter")
	}

	wait, err := limiter.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer limiter.Release()

	if err := fn(); err != nil {
		return wait, err
	}
	return wait, nil
}

// ParseIntOption reads an optional integer option from a config map.
// Missing or nil values return defaultValue.
func ParseIntOption(cfg map[string]any, key string, defaultValue int) (int, error) {
	value, ok := cfg[key]
	if !ok || value == nil {
		return defaultValue, nil
	}

	switch typed := value.(type) {
	case int:
		return typed, nil
	case int8:
		return int(typed), nil
	case int16:
		return int(typed), nil
	case int32:
		return int(typed), nil
	case int64:
		return int(typed), nil
	case uint:
		return int(typed), nil
	case uint8:
		return int(typed), nil
	case uint16:
		return int(typed), nil
	case uint32:
		return int(typed), nil
	case uint64:
		return int(typed), nil
	case float64:
		return int(typed), nil
	case string:
		parsed, err := strconv.Atoi(typed)
		if err != nil {
			return 0, fmt.Errorf("invalid %s %q: %w", key, typed, err)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("unsupported %s type %T", key, value)
	}
}

// ParseDurationOption reads an optional duration option from a config map.
// Missing or nil values return defaultValue.
func ParseDurationOption(cfg map[string]any, key string, defaultValue time.Duration) (time.Duration, error) {
	value, ok := cfg[key]
	if !ok || value == nil {
		return defaultValue, nil
	}

	switch typed := value.(type) {
	case time.Duration:
		return typed, nil
	case string:
		parsed, err := time.ParseDuration(typed)
		if err != nil {
			return 0, fmt.Errorf("invalid %s %q: %w", key, typed, err)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("unsupported %s type %T", key, value)
	}
}
