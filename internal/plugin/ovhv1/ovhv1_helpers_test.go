package ovhv1

import (
	"fmt"
	"testing"
)

func TestCanonicalOVHKeyAndTagAlgo(t *testing.T) {
	k := ovhKey{ID: 1, Tag: 100, Algorithm: 13, Flags: 257, PublicKey: "pub", Status: "ok"}

	wantCanon := fmt.Sprintf("%d/%d/%d/%s", k.Tag, k.Algorithm, k.Flags, k.PublicKey)
	if got := canonicalOVHKey(k); got != wantCanon {
		t.Fatalf("canonicalOVHKey: got %q want %q", got, wantCanon)
	}

	wantTagAlgo := fmt.Sprintf("%d/%d", k.Tag, k.Algorithm)
	if got := tagAlgoKey(uint16(k.Tag), uint8(k.Algorithm)); got != wantTagAlgo {
		t.Fatalf("tagAlgoKey: got %q want %q", got, wantTagAlgo)
	}
	if got := tagAlgoKeyFromOVH(k); got != wantTagAlgo {
		t.Fatalf("tagAlgoKeyFromOVH: got %q want %q", got, wantTagAlgo)
	}
}

func TestIsDNSSECTask(t *testing.T) {
	positives := []string{
		"ZoneDnssecDsCreate",
		"some dsrecord",
		"domainDS",
	}
	for _, s := range positives {
		if !isDNSSECTask(s) {
			t.Fatalf("expected %q to be detected as DNSSEC task", s)
		}
	}

	if isDNSSECTask("unrelated task") {
		t.Fatalf("expected unrelated string not to be detected as DNSSEC task")
	}
}
