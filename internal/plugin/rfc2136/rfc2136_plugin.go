package rfc2136

import (
	"fmt"
	"log/slog"
	"math"
	"net"
	"strconv"

	"github.com/miekg/dns"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/plugin"
)

func init() {
	plugin.Register(pluginName, func() plugin.Plugin {
		return &RFC2136Plugin{}
	})
}

func (p *RFC2136Plugin) Name() string { return pluginName }

func (p *RFC2136Plugin) Capabilities() plugin.Capabilities {
	return plugin.Capabilities{RequiresCDNSKEY: false}
}

func (p *RFC2136Plugin) Init(_ map[string]any, logger *slog.Logger) error {
	p.log = logger
	return nil
}

func (p *RFC2136Plugin) NewGroup(groupName string, cfg map[string]any) (plugin.GroupPlugin, error) {
	server, _ := cfg["server"].(string)
	if server == "" {
		return nil, fmt.Errorf("%s: group %s: missing required field 'server'", pluginName, groupName)
	}

	port, err := plugin.ParseIntOption(cfg, "port", defaultPort)
	if err != nil {
		return nil, fmt.Errorf("%s: group %s: %w", pluginName, groupName, err)
	}
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("%s: group %s: port must be between 1 and 65535", pluginName, groupName)
	}

	var ttl *uint32
	if cfg["ttl"] != nil {
		ttlInt, err := plugin.ParseIntOption(cfg, "ttl", int(defaultTTL))
		if err != nil {
			return nil, fmt.Errorf("%s: group %s: %w", pluginName, groupName, err)
		}
		if ttlInt <= 0 || ttlInt > math.MaxUint32 {
			return nil, fmt.Errorf("%s: group %s: ttl must be between 1 and %d", pluginName, groupName, uint32(math.MaxUint32))
		}
		t := uint32(ttlInt)
		ttl = &t
	}

	var auth authConfig
	if cfg["tsig"] != nil {
		tsigMap, ok := cfg["tsig"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: group %s: [plugin_config.tsig] must be a table", pluginName, groupName)
		}
		var err error
		auth, err = parseTSIGConfig(pluginName, groupName, tsigMap)
		if err != nil {
			return nil, err
		}
	}

	if cfg["sig0"] != nil {
		return nil, fmt.Errorf("%s: group %s: SIG(0) authentication is not yet implemented", pluginName, groupName)
	}

	// Optional timeout override; zero means use the library default (no timeout).
	timeout, err := plugin.ParseDurationOption(cfg, "timeout", 0)
	if err != nil {
		return nil, fmt.Errorf("%s: group %s: %w", pluginName, groupName, err)
	}

	c := &dns.Client{Net: "tcp", Timeout: timeout}
	if auth.mode == authTSIG {
		c.TsigSecret = map[string]string{auth.tsig.keyName: auth.tsig.secret}
	}

	addr := net.JoinHostPort(server, strconv.Itoa(port))

	log := p.logger().With("group", groupName)
	log.Info("rfc2136 group configured",
		"server", server,
		"port", port,
		"auth", authModeName(auth.mode),
		"timeout", timeout,
	)

	return &RFC2136Group{
		plugin: p,
		log:    log,
		addr:   addr,
		ttl:    ttl,
		client: c,
		auth:   auth,
	}, nil
}

func parseTSIGConfig(pluginName, groupName string, cfg map[string]any) (authConfig, error) {
	keyName, _ := cfg["key_name"].(string)
	if keyName == "" {
		return authConfig{}, fmt.Errorf("%s: group %s: [plugin_config.tsig] missing required field 'key_name'", pluginName, groupName)
	}
	secret, _ := cfg["secret"].(string)
	if secret == "" {
		return authConfig{}, fmt.Errorf("%s: group %s: [plugin_config.tsig] missing required field 'secret'", pluginName, groupName)
	}
	algorithm, _ := cfg["algorithm"].(string)
	if algorithm == "" {
		algorithm = dns.HmacSHA256
	}
	return authConfig{
		mode: authTSIG,
		tsig: &tsigConfig{
			keyName:   dns.Fqdn(keyName),
			algorithm: dns.Fqdn(algorithm),
			secret:    secret,
		},
	}, nil
}

func authModeName(m authMode) string {
	switch m {
	case authTSIG:
		return "tsig"
	default:
		return "none"
	}
}
