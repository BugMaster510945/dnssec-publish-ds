package logging

import (
	"log/slog"
	"os"
	"strings"
)

const credentialMask = "*****"

// Setup configures the global slog logger with the given level.
// Output goes to stdout (compatible with systemd/journalctl).
func Setup(level string) {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: lvl,
	})
	slog.SetDefault(slog.New(handler))
}

// MaskCredential replaces a credential value with "*****".
func MaskCredential(v string) string {
	if v == "" {
		return v
	}
	return credentialMask
}

// GroupLogger returns a logger with group attribute preset.
func GroupLogger(group string) *slog.Logger {
	return slog.With("group", group)
}

// ZoneLogger returns a logger with group and zone attributes preset.
func ZoneLogger(group, zone string) *slog.Logger {
	return slog.With("group", group, "zone", zone)
}
