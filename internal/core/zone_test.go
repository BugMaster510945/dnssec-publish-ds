package core

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/plugin"
	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/status"
)

type fakeZoneDNS struct {
	keys    []plugin.KeyRecord
	isRem   bool
	keysErr error

	ds    []*dns.DS
	dsErr error

	queryDSCalls int
}

func (f *fakeZoneDNS) FetchZoneKeys(zone string) ([]plugin.KeyRecord, bool, error) {
	return f.keys, f.isRem, f.keysErr
}

func (f *fakeZoneDNS) QueryDS(zone string) ([]*dns.DS, error) {
	f.queryDSCalls++
	return f.ds, f.dsErr
}

type fakePlugin struct {
	requiresCDNSKEY bool
	updateErr       error
	updateResult    plugin.UpdateResult
	continueResult  plugin.UpdateResult

	updateCalls int
}

func (f *fakePlugin) Name() string {
	return "fake"
}

func (f *fakePlugin) Capabilities() plugin.Capabilities {
	return plugin.Capabilities{RequiresCDNSKEY: f.requiresCDNSKEY}
}

func (f *fakePlugin) Update(ctx context.Context, req plugin.UpdateRequest) (plugin.UpdateResult, error) {
	f.updateCalls++
	if f.updateErr != nil {
		return plugin.UpdateResult{}, f.updateErr
	}
	if len(req.Raw) != 0 {
		if f.continueResult.Raw == nil && !f.continueResult.InProgress {
			return plugin.UpdateResult{}, nil
		}
		return f.continueResult, nil
	}
	if f.updateResult.Raw == nil && !f.updateResult.InProgress {
		f.updateResult.InProgress = true
		f.updateResult.Raw = map[string]any{"task_id": "task-1"}
		f.updateResult.NextWait = time.Nanosecond
	}
	return f.updateResult, nil
}

func newTestStore(t *testing.T) *status.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "status.json")
	s := status.NewStore(path)
	s.Load()
	return s
}

func TestZoneRunCycleAlignedNoUpdate(t *testing.T) {
	fakeDNS := &fakeZoneDNS{
		keys: []plugin.KeyRecord{
			{Tag: 12345, Algorithm: 13, DigestType: dns.SHA256, Digest: "ABCD"},
		},
		ds: []*dns.DS{{KeyTag: 12345, Algorithm: 13, DigestType: dns.SHA256, Digest: "ABCD"}},
	}
	fakePlugin := &fakePlugin{}
	zr := NewZoneRunner("g1", "example.com", time.Hour, 5*time.Minute, fakePlugin, fakeDNS, newTestStore(t), true)

	_, _ = zr.runStep(context.Background())

	if fakePlugin.updateCalls != 0 {
		t.Fatalf("expected no update call when aligned, got %d", fakePlugin.updateCalls)
	}
}

func TestZoneRunCycleMisalignedUpdateAndComplete(t *testing.T) {
	fakeDNS := &fakeZoneDNS{
		keys: []plugin.KeyRecord{
			{Tag: 22222, Algorithm: 13, DigestType: dns.SHA256, Digest: "BBBB"},
		},
		ds: []*dns.DS{{KeyTag: 11111, Algorithm: 13, DigestType: dns.SHA256, Digest: "AAAA"}},
	}
	fakePlugin := &fakePlugin{continueResult: plugin.UpdateResult{InProgress: false, Raw: nil}}
	store := newTestStore(t)
	zr := NewZoneRunner("g1", "example.com", time.Hour, 5*time.Minute, fakePlugin, fakeDNS, store, true)

	_, _ = zr.runStep(context.Background())
	_, _ = zr.runStep(context.Background())

	if fakePlugin.updateCalls < 2 {
		t.Fatalf("expected update continuation to happen, got %d calls", fakePlugin.updateCalls)
	}
	if st := store.Get("example.com"); st != nil {
		t.Fatalf("expected persisted polling state to be cleared after completion")
	}
}

func TestZoneRunCycleUpdateErrorDoesNotPersistState(t *testing.T) {
	fakeDNS := &fakeZoneDNS{
		keys: []plugin.KeyRecord{
			{Tag: 22222, Algorithm: 13, DigestType: dns.SHA256, Digest: "BBBB"},
		},
		ds: []*dns.DS{{KeyTag: 11111, Algorithm: 13, DigestType: dns.SHA256, Digest: "AAAA"}},
	}
	fakePlugin := &fakePlugin{updateErr: errors.New("provider failure")}
	store := newTestStore(t)
	zr := NewZoneRunner("g1", "example.com", time.Hour, 5*time.Minute, fakePlugin, fakeDNS, store, true)

	_, _ = zr.runStep(context.Background())

	if fakePlugin.updateCalls != 1 {
		t.Fatalf("expected one update attempt, got %d", fakePlugin.updateCalls)
	}
	if st := store.Get("example.com"); st != nil {
		t.Fatalf("expected no persisted state on update error")
	}
}

func TestZoneRunCycleRequiresCDNSKEYSkipsWhenMissing(t *testing.T) {
	fakeDNS := &fakeZoneDNS{
		keys: []plugin.KeyRecord{
			{Tag: 12345, Algorithm: 13, DigestType: dns.SHA256, Digest: "ABCD"},
		},
	}
	fakePlugin := &fakePlugin{requiresCDNSKEY: true}
	zr := NewZoneRunner("g1", "example.com", time.Hour, 5*time.Minute, fakePlugin, fakeDNS, newTestStore(t), true)

	_, _ = zr.runStep(context.Background())

	if fakePlugin.updateCalls != 0 {
		t.Fatalf("expected no update when CDNSKEY is required but missing")
	}
	if fakeDNS.queryDSCalls != 0 {
		t.Fatalf("expected DS query to be skipped when capability check fails")
	}
}

func TestZoneRunCycleClearsStateOnOwnerMismatch(t *testing.T) {
	fakeDNS := &fakeZoneDNS{
		keys: []plugin.KeyRecord{
			{Tag: 12345, Algorithm: 13, DigestType: dns.SHA256, Digest: "ABCD"},
		},
		ds: []*dns.DS{{KeyTag: 12345, Algorithm: 13, DigestType: dns.SHA256, Digest: "ABCD"}},
	}
	fakePlugin := &fakePlugin{}
	store := newTestStore(t)
	store.Set("example.com", &status.ZoneState{
		InProgress: true,
		Group:      "other-group",
		Plugin:     "fake",
		Raw:        map[string]any{"task_id": "task-1"},
	})

	zr := NewZoneRunner("g1", "example.com", time.Hour, 5*time.Minute, fakePlugin, fakeDNS, store, true)

	_, _ = zr.runStep(context.Background())

	if st := store.Get("example.com"); st != nil {
		t.Fatalf("expected mismatched persisted state to be cleared")
	}
	if fakePlugin.updateCalls != 0 {
		t.Fatalf("expected no continuation call from mismatched state, got %d", fakePlugin.updateCalls)
	}
}
