package helpers

import (
	"strings"

	"github.com/miekg/dns"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/plugin"
)

// ExtractRR filters a slice of DNS resource records and returns only records of type T.
func ExtractRR[T dns.RR](rrs []dns.RR) []T {
	out := make([]T, 0, len(rrs))
	for _, rr := range rrs {
		if v, ok := rr.(T); ok {
			out = append(out, v)
		}
	}
	return out
}

// KeyRecordFromDS converts a *dns.DS to a simplified plugin.KeyRecord
// containing only the four CDS identity fields with a normalized (uppercase) digest.
// The result is suitable for use as a map key.
func KeyRecordFromDS(ds *dns.DS) plugin.KeyRecord {
	return plugin.KeyRecord{
		Tag:        ds.KeyTag,
		Algorithm:  ds.Algorithm,
		DigestType: ds.DigestType,
		Digest:     strings.ToUpper(ds.Digest),
	}
}

// NormKeyRecord returns a simplified plugin.KeyRecord with only the four CDS
// identity fields and a normalized (uppercase) digest, suitable as a map key.
func NormKeyRecord(kr plugin.KeyRecord) plugin.KeyRecord {
	return plugin.KeyRecord{
		Tag:        kr.Tag,
		Algorithm:  kr.Algorithm,
		DigestType: kr.DigestType,
		Digest:     strings.ToUpper(kr.Digest),
	}
}

// CompareDS computes which DS records must be added and removed to converge
// the current published DS records toward the desired set.
// Digest comparison is case-insensitive.
func CompareDS(current []*dns.DS, desired []plugin.KeyRecord) (toAdd, toRemove []plugin.KeyRecord) {
	currentSet := make(map[plugin.KeyRecord]bool)
	for _, d := range current {
		currentSet[KeyRecordFromDS(d)] = true
	}

	desiredSet := make(map[plugin.KeyRecord]bool)
	for _, d := range desired {
		id := NormKeyRecord(d)
		desiredSet[id] = true
		if !currentSet[id] {
			toAdd = append(toAdd, d)
		}
	}

	for _, d := range current {
		id := KeyRecordFromDS(d)
		if !desiredSet[id] {
			toRemove = append(toRemove, id)
		}
	}

	return toAdd, toRemove
}
