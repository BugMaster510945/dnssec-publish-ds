package rfc2136

import (
	"log/slog"

	"github.com/miekg/dns"
)

const pluginName = "rfc2136"

const (
	defaultPort = 53
	defaultTTL  = uint32(3600)
)

type authMode int

const (
	authNone authMode = iota
	authTSIG
)

type tsigConfig struct {
	keyName   string
	algorithm string
	secret    string
}

type authConfig struct {
	mode authMode
	tsig *tsigConfig
}

// RFC2136Plugin is the global plugin instance for the rfc2136 provider.
type RFC2136Plugin struct {
	log *slog.Logger
}

// RFC2136Group is the per-group plugin instance for the rfc2136 provider.
// client is pre-configured at group creation (Net=tcp, optional Timeout, optional TsigSecret).
type RFC2136Group struct {
	plugin *RFC2136Plugin
	log    *slog.Logger
	addr   string // host:port, computed once at NewGroup
	ttl    *uint32
	client *dns.Client
	auth   authConfig
}

func (p *RFC2136Plugin) logger() *slog.Logger {
	if p.log != nil {
		return p.log
	}
	return slog.Default()
}

func (g *RFC2136Group) logger() *slog.Logger {
	if g.log != nil {
		return g.log
	}
	return slog.Default()
}

func (p *RFC2136Plugin) Close() error { return nil }

func (g *RFC2136Group) Close() error { return nil }
