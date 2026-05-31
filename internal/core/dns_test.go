package core

import (
	"testing"

	"github.com/miekg/dns"
)

func TestBuildFromCDS(t *testing.T) {
	var c1 dns.CDS
	c1.KeyTag = 1000
	c1.Algorithm = 13
	c1.DigestType = dns.SHA256
	c1.Digest = "deadbeef"
	var c2 dns.CDS
	c2.KeyTag = 2000
	c2.Algorithm = 8
	c2.DigestType = dns.SHA1
	c2.Digest = "cafebabe"
	cds := []*dns.CDS{&c1, &c2}

	recs := buildFromCDS(cds)
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}
	if recs[0].Tag != 1000 || recs[0].Algorithm != 13 || recs[0].DigestType != dns.SHA256 || recs[0].Digest != "deadbeef" {
		t.Fatalf("unexpected first record: %+v", recs[0])
	}
	if recs[1].Tag != 2000 || recs[1].Algorithm != 8 || recs[1].DigestType != dns.SHA1 || recs[1].Digest != "cafebabe" {
		t.Fatalf("unexpected second record: %+v", recs[1])
	}
}

func TestAlgoAndDigestString(t *testing.T) {
	// Use values present in miekg/dns maps to assert mapping correctness
	algo := uint8(13)
	if got := algoString(algo); got == "UNKNOWN" {
		t.Fatalf("expected algoString(%d) to be known, got UNKNOWN", algo)
	}

	dt := uint8(dns.SHA256)
	if got := digestTypeString(dt); got == "UNKNOWN" {
		t.Fatalf("expected digestTypeString(%d) to be known, got UNKNOWN", dt)
	}

	// Unknown values must return "UNKNOWN"
	if algoString(0xFF) != "UNKNOWN" {
		t.Fatalf("expected unknown algorithm to return UNKNOWN")
	}
	if digestTypeString(0xFF) != "UNKNOWN" {
		t.Fatalf("expected unknown digest type to return UNKNOWN")
	}
}
