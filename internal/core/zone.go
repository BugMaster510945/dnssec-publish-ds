package core

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/miekg/dns"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/core/helpers"
	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/logging"
	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/plugin"
	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/status"
)

// Zone has two communication modes:
// - InProgress false: sleeping, will check again at next checkInterval.
// - InProgress true: an operation is being tracked, Update is called again at NextWait intervals.
// Plugins may use Raw to store their own internal FSM state (optional, opaque to core).
const (
	defaultPollInterval = 30 * time.Second
	initialJitterMax    = 5 * time.Minute
)

// ZoneRunner manages the lifecycle of a single zone.
type ZoneRunner struct {
	group              string
	zone               string
	checkInterval      time.Duration
	errorRetryInterval time.Duration
	plugin             plugin.GroupPlugin
	dns                zoneDNSClient
	store              *status.Store
	log                *slog.Logger
	skipInitialJitter  bool
}

type zoneDNSClient interface {
	FetchZoneKeys(ctx context.Context, zone string) ([]plugin.KeyRecord, bool, error)
	QueryDS(ctx context.Context, zone string) ([]*dns.DS, error)
}

// NewZoneRunner creates a runner for a zone.
func NewZoneRunner(group, zone string, checkInterval, errorRetryInterval time.Duration, p plugin.GroupPlugin, dns zoneDNSClient, store *status.Store, skipInitialJitter bool) *ZoneRunner {
	return &ZoneRunner{
		group:              group,
		zone:               zone,
		checkInterval:      checkInterval,
		errorRetryInterval: errorRetryInterval,
		plugin:             p,
		dns:                dns,
		store:              store,
		log:                logging.ZoneLogger(group, zone),
		skipInitialJitter:  skipInitialJitter,
	}
}

// Run starts the zone state machine. It blocks until the context is cancelled.
func (z *ZoneRunner) Run(ctx context.Context) {
	if z.skipInitialJitter {
		z.log.Info("initial sleep bypassed")
	} else {
		jitter := time.Duration(rand.Int64N(int64(initialJitterMax)))
		z.log.Info("initial sleep before first check", "jitter", jitter)
		if !z.sleep(ctx, jitter) {
			return
		}
	}

	// Main loop
	for {
		interval, ok := z.runStep(ctx)
		if !ok {
			return
		}
		if !z.sleepForInterval(ctx, interval) {
			return
		}
	}
}

func (z *ZoneRunner) runStep(ctx context.Context) (time.Duration, bool) {
	state := z.loadOwnedState()
	req, active, err := z.prepareUpdateRequest(ctx, state)
	if err != nil {
		return z.errorRetryInterval, ctx.Err() == nil
	}

	if req == nil {
		return z.checkInterval, ctx.Err() == nil
	}

	result, err := z.plugin.Update(ctx, *req)
	if err != nil {
		if active {
			z.log.Error("failed to continue update", "error", err)
		} else {
			z.log.Error("failed to submit update", "error", err)
		}
		return z.errorRetryInterval, ctx.Err() == nil
	}

	sleepFor := z.applyUpdateResult(result)
	return sleepFor, ctx.Err() == nil
}

func (z *ZoneRunner) loadOwnedState() *status.ZoneState {
	state := z.store.Get(z.stateKey())
	if state == nil {
		return nil
	}

	if state.Group == z.group && state.Plugin == z.plugin.Name() {
		return state
	}

	z.log.Warn("discarding persisted state from different owner",
		"stored_group", state.Group,
		"stored_plugin", state.Plugin,
		"current_group", z.group,
		"current_plugin", z.plugin.Name(),
	)
	z.store.Clear(z.stateKey())
	if err := z.store.Save(); err != nil {
		z.log.Error("failed to save status", "error", err)
	}
	return nil
}

func (z *ZoneRunner) prepareUpdateRequest(ctx context.Context, state *status.ZoneState) (*plugin.UpdateRequest, bool, error) {
	if state != nil && state.InProgress {
		return &plugin.UpdateRequest{
			Zone: z.zone,
			Raw:  state.Raw,
		}, true, nil
	}

	z.log.Info("checking zone alignment")

	desiredKeys, isRemoval, err := z.dns.FetchZoneKeys(ctx, z.zone)
	if err != nil {
		z.log.Error("failed to fetch zone keys", "error", err)
		return nil, false, err
	}

	z.logDesiredKeys(desiredKeys)

	if isRemoval {
		z.log.Warn("zone has sentinel CDS/CDNSKEY (algorithm 0), DNSSEC removal requested - not supported, skipping")
		return nil, false, nil
	}

	if len(desiredKeys) == 0 {
		z.log.Info("no CDS/CDNSKEY records found, nothing to do")
		return nil, false, nil
	}

	if z.plugin.Capabilities().RequiresCDNSKEY {
		for _, k := range desiredKeys {
			if k.PublicKey == nil {
				z.log.Error("plugin requires CDNSKEY but only CDS is available")
				return nil, false, nil
			}
		}
	}

	currentDS, err := z.dns.QueryDS(ctx, z.zone)
	if err != nil {
		z.log.Error("failed to query DS records", "error", err)
		return nil, false, err
	}

	z.logCurrentDS(currentDS)

	toAdd, toRemove := helpers.CompareDS(currentDS, desiredKeys)
	if len(toAdd) == 0 && len(toRemove) == 0 {
		z.log.Info("zone is aligned, no changes needed")
		return nil, false, nil
	}

	z.logModifications(toAdd, toRemove)
	z.log.Info("zone is misaligned",
		"ds_add", len(toAdd),
		"ds_remove", len(toRemove),
	)

	return &plugin.UpdateRequest{
		Zone:     z.zone,
		ToAdd:    toAdd,
		ToRemove: toRemove,
	}, false, nil
}

func (z *ZoneRunner) applyUpdateResult(result plugin.UpdateResult) time.Duration {
	if !result.InProgress {
		z.store.Clear(z.stateKey())
		if err := z.store.Save(); err != nil {
			z.log.Error("failed to save status", "error", err)
		}
		return z.checkInterval
	}

	z.persistState(true, result.Raw)
	if err := z.store.Save(); err != nil {
		z.log.Error("failed to save status", "error", err)
	}

	nextWait := defaultPollInterval
	if result.NextWait > 0 {
		nextWait = result.NextWait
	}
	z.log.Debug("operation still in progress", "next_wait", nextWait)
	return nextWait
}

func (z *ZoneRunner) sleepForInterval(ctx context.Context, interval time.Duration) bool {
	if ctx.Err() != nil {
		return false
	}
	z.log.Info("sleeping", "interval", interval)
	return z.sleep(ctx, interval)
}

// sleep waits for the given duration or until the context is cancelled.
// Returns false if the context was cancelled.
func (z *ZoneRunner) sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (z *ZoneRunner) stateKey() string {
	return z.zone
}

func (z *ZoneRunner) persistState(inProgress bool, raw map[string]any) {
	z.store.Set(z.stateKey(), &status.ZoneState{
		InProgress: inProgress,
		Group:      z.group,
		Plugin:     z.plugin.Name(),
		Raw:        raw,
	})
}

// logDesiredKeys logs detailed information about fetched CDS/CDNSKEY records.
func (z *ZoneRunner) logDesiredKeys(keys []plugin.KeyRecord) {
	if len(keys) == 0 {
		z.log.Debug("desired keys: empty")
		return
	}
	z.log.Debug("desired keys fetched", "count", len(keys))
	for i, k := range keys {
		flags := ""
		if k.Flags != nil {
			flags = fmt.Sprintf("%d", *k.Flags)
		}
		z.log.Debug(fmt.Sprintf("desired_key[%d]", i),
			"tag", k.Tag,
			"algorithm", algoString(k.Algorithm),
			"digest_type", digestTypeString(k.DigestType),
			"digest", k.Digest[:min(16, len(k.Digest))]+"...",
			"flags", flags,
		)
	}
}

// logCurrentDS logs detailed information about current DS records.
func (z *ZoneRunner) logCurrentDS(records []*dns.DS) {
	if len(records) == 0 {
		z.log.Debug("current DS records: empty")
		return
	}
	z.log.Debug("current DS records queried", "count", len(records))
	for i, ds := range records {
		z.log.Debug(fmt.Sprintf("current_ds[%d]", i),
			"tag", ds.KeyTag,
			"algorithm", algoString(ds.Algorithm),
			"digest_type", digestTypeString(ds.DigestType),
			"digest", ds.Digest[:min(16, len(ds.Digest))]+"...",
		)
	}
}

// logModifications logs detailed information about DS records to add and remove.
func (z *ZoneRunner) logModifications(toAdd, toRemove []plugin.KeyRecord) {
	if len(toAdd) > 0 {
		z.log.Debug("DS records to add", "count", len(toAdd))
		for i, k := range toAdd {
			z.log.Debug(fmt.Sprintf("to_add[%d]", i),
				"tag", k.Tag,
				"algorithm", algoString(k.Algorithm),
				"digest_type", digestTypeString(k.DigestType),
				"digest", k.Digest[:min(16, len(k.Digest))]+"...",
			)
		}
	}
	if len(toRemove) > 0 {
		z.log.Debug("DS records to remove", "count", len(toRemove))
		for i, k := range toRemove {
			z.log.Debug(fmt.Sprintf("to_remove[%d]", i),
				"tag", k.Tag,
				"algorithm", algoString(k.Algorithm),
				"digest_type", digestTypeString(k.DigestType),
				"digest", k.Digest[:min(16, len(k.Digest))]+"...",
			)
		}
	}
}

// algoString returns the algorithm name for a DNSSEC algorithm ID.
func algoString(algo uint8) string {
	if name, ok := dns.AlgorithmToString[algo]; ok {
		return name
	}
	return "UNKNOWN"
}

// digestTypeString returns the digest type name for a DS digest type ID.
func digestTypeString(dt uint8) string {
	if name, ok := dns.HashToString[dt]; ok {
		return name
	}
	return "UNKNOWN"
}
