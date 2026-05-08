package ovhv1

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ovh/go-ovh/ovh"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/plugin"
)

func init() {
	plugin.Register(pluginName, func() plugin.Plugin {
		return &OVHv1Plugin{}
	})
}

func (p *OVHv1Plugin) Name() string {
	return pluginName
}

func (p *OVHv1Plugin) Capabilities() plugin.Capabilities {
	return plugin.Capabilities{RequiresCDNSKEY: true}
}

func (p *OVHv1Plugin) groupLogger(groupName string) *slog.Logger {
	return p.logger().With("group", groupName)
}

func (p *OVHv1Plugin) Init(globalCfg map[string]any, logger *slog.Logger) error {
	p.log = logger

	maxConcurrency, err := plugin.ParseIntOption(globalCfg, "max_concurrency", defaultMaxConcurrency)
	if err != nil {
		return fmt.Errorf("%s: %w", pluginName, err)
	}

	throttle, err := plugin.NewLimiter(maxConcurrency)
	if err != nil {
		return fmt.Errorf("%s: invalid max_concurrency: %w", pluginName, err)
	}

	p.throttle = throttle
	p.logger().Info("configured ovh api throttling", "max_concurrency", maxConcurrency)
	return nil
}

func (p *OVHv1Plugin) NewGroup(groupName string, cfg map[string]any) (plugin.GroupPlugin, error) {
	if _, ok := cfg["max_concurrency"]; ok {
		return nil, fmt.Errorf(
			"%s: max_concurrency must be configured in [plugins.\"%s\"], not in [group.%s.plugin_config]",
			pluginName,
			pluginName,
			groupName,
		)
	}

	endpoint, _ := cfg["endpoint"].(string)
	if endpoint == "" {
		endpoint = "ovh-eu"
	}
	appKey, _ := cfg["application_key"].(string)
	appSecret, _ := cfg["application_secret"].(string)
	consumerKey, _ := cfg["consumer_key"].(string)

	if appKey == "" || appSecret == "" || consumerKey == "" {
		return nil, fmt.Errorf("%s: missing credentials (application_key, application_secret, consumer_key)", pluginName)
	}

	client, err := ovh.NewClient(endpoint, appKey, appSecret, consumerKey)
	if err != nil {
		return nil, fmt.Errorf("%s: creating client: %w", pluginName, err)
	}

	groupPlugin := &OVHv1Group{
		plugin: p,
		client: client,
		log:    p.groupLogger(groupName),
	}
	client.Logger = ovhSlogLogger{log: groupPlugin.logger().With("component", "ovh_http")}

	if err := groupPlugin.checkCredentials(context.Background()); err != nil {
		return nil, err
	}
	return groupPlugin, nil
}
