package core

import (
	"testing"

	"github.com/miekg/dns"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/plugin"
)

func TestCompareDSAligned(t *testing.T) {
	current := []*dns.DS{
		{KeyTag: 12345, Algorithm: 13, DigestType: dns.SHA256, Digest: "ABCD"},
	}
	desired := []plugin.KeyRecord{
		{Tag: 12345, Algorithm: 13, DigestType: dns.SHA256, Digest: "abcd"},
	}

	toAdd, toRemove := CompareDS(current, desired)
	if len(toAdd) != 0 || len(toRemove) != 0 {
		t.Fatalf("expected aligned sets, got add=%d remove=%d", len(toAdd), len(toRemove))
	}
}

func TestCompareDSDetectsAddAndRemove(t *testing.T) {
	current := []*dns.DS{
		{KeyTag: 11111, Algorithm: 13, DigestType: dns.SHA256, Digest: "AAAA"},
	}
	desired := []plugin.KeyRecord{
		{Tag: 22222, Algorithm: 13, DigestType: dns.SHA256, Digest: "BBBB"},
	}

	toAdd, toRemove := CompareDS(current, desired)
	if len(toAdd) != 1 {
		t.Fatalf("expected 1 addition, got %d", len(toAdd))
	}
	if len(toRemove) != 1 {
		t.Fatalf("expected 1 removal, got %d", len(toRemove))
	}
	if toAdd[0].Tag != 22222 {
		t.Fatalf("unexpected toAdd tag: %d", toAdd[0].Tag)
	}
	if toRemove[0].Tag != 11111 {
		t.Fatalf("unexpected toRemove tag: %d", toRemove[0].Tag)
	}
}
