package ovhv1

import (
	"context"
	"fmt"
	"time"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/plugin"
)

const (
	defaultMaxConcurrency    = 1
	throttleLogWaitThreshold = 10 * time.Second
)

func (p *OVHv1Group) doWithThrottle(ctx context.Context, method string, path string, op func(context.Context) error) error {
	if p.plugin == nil {
		return fmt.Errorf("%s: throttle not initialized", pluginName)
	}

	wait, err := plugin.WithLimiter(ctx, p.plugin.throttle, func() error {
		return op(ctx)
	})
	if err != nil {
		return err
	}

	if wait >= throttleLogWaitThreshold {
		p.logger().Debug("ovh_api_throttle_wait",
			"method", method,
			"path", path,
			"wait", wait,
			"max_concurrency", p.plugin.throttle.Limit(),
		)
	}

	return nil
}

func (p *OVHv1Group) getWithContext(ctx context.Context, path string, res any) error {
	return p.doWithThrottle(ctx, "GET", path, func(ctx context.Context) error {
		return p.client.GetWithContext(ctx, path, res)
	})
}

func (p *OVHv1Group) postWithContext(ctx context.Context, path string, req any, res any) error {
	return p.doWithThrottle(ctx, "POST", path, func(ctx context.Context) error {
		return p.client.PostWithContext(ctx, path, req, res)
	})
}
