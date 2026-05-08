package core

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/plugin"
)

// DNSClient handles DNSSEC-validated DNS queries.
type DNSClient struct {
	timeout time.Duration
	servers []string
}

// NewDNSClient creates a DNS client using the system resolver configuration.
func NewDNSClient(timeout time.Duration) (*DNSClient, error) {
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("reading /etc/resolv.conf: %w", err)
	}
	servers := make([]string, len(conf.Servers))
	for i, s := range conf.Servers {
		servers[i] = s + ":" + conf.Port
	}
	return &DNSClient{timeout: timeout, servers: servers}, nil
}

// query performs a DNSSEC-validated DNS query and returns the answer section.
func (c *DNSClient) query(name string, qtype uint16) ([]dns.RR, error) {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.SetEdns0(4096, true) // DO flag
	m.RecursionDesired = true

	client := &dns.Client{Timeout: c.timeout}

	if len(c.servers) == 0 {
		return nil, fmt.Errorf("no DNS servers configured for %s %s", name, dns.TypeToString[qtype])
	}

	var reasons []string
	for _, server := range c.servers {
		r, _, err := client.Exchange(m, server)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("%s: exchange failed: %v", server, err))
			continue
		}
		if r.Rcode != dns.RcodeSuccess {
			reasons = append(reasons, fmt.Sprintf("%s: rcode %s", server, dns.RcodeToString[r.Rcode]))
			continue
		}
		if !r.AuthenticatedData {
			reasons = append(reasons, fmt.Sprintf("%s: AD flag not set", server))
			continue
		}
		return r.Answer, nil
	}
	return nil, fmt.Errorf("no DNSSEC-validated response for %s %s (%s)", name, dns.TypeToString[qtype], strings.Join(reasons, "; "))
}

// queryNoADCheck retrieves a DNS response without requiring AD flag.
// Used as fallback for zones where authoritative server doesn't validate.
func (c *DNSClient) queryNoADCheck(name string, qtype uint16) ([]dns.RR, error) {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	m.SetEdns0(4096, true) // DO flag for DNSSEC records
	m.RecursionDesired = true

	client := &dns.Client{Timeout: c.timeout}

	if len(c.servers) == 0 {
		return nil, fmt.Errorf("no DNS servers configured for %s %s", name, dns.TypeToString[qtype])
	}

	var lastErr error
	for _, server := range c.servers {
		r, _, err := client.Exchange(m, server)
		if err != nil {
			lastErr = err
			continue
		}
		if r.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("rcode %s", dns.RcodeToString[r.Rcode])
			continue
		}
		return r.Answer, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no response from any server")
	}
	return nil, fmt.Errorf("unable to retrieve %s %s: %w", name, dns.TypeToString[qtype], lastErr)
}

// QueryCDNSKEY returns the CDNSKEY records for a zone.
func (c *DNSClient) QueryCDNSKEY(zone string) ([]*dns.CDNSKEY, error) {
	rrs, err := c.query(zone, dns.TypeCDNSKEY)
	if err != nil {
		return nil, err
	}
	var keys []*dns.CDNSKEY
	for _, rr := range rrs {
		if k, ok := rr.(*dns.CDNSKEY); ok {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// queryCDNSKEYNoADCheck returns CDNSKEY records without AD requirement.
func (c *DNSClient) queryCDNSKEYNoADCheck(zone string) ([]*dns.CDNSKEY, error) {
	rrs, err := c.queryNoADCheck(zone, dns.TypeCDNSKEY)
	if err != nil {
		return nil, err
	}
	var keys []*dns.CDNSKEY
	for _, rr := range rrs {
		if k, ok := rr.(*dns.CDNSKEY); ok {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// QueryCDS returns the CDS records for a zone.
func (c *DNSClient) QueryCDS(zone string) ([]*dns.CDS, error) {
	rrs, err := c.query(zone, dns.TypeCDS)
	if err != nil {
		return nil, err
	}
	var cds []*dns.CDS
	for _, rr := range rrs {
		if c, ok := rr.(*dns.CDS); ok {
			cds = append(cds, c)
		}
	}
	return cds, nil
}

// queryCDSNoADCheck returns CDS records without AD requirement.
func (c *DNSClient) queryCDSNoADCheck(zone string) ([]*dns.CDS, error) {
	rrs, err := c.queryNoADCheck(zone, dns.TypeCDS)
	if err != nil {
		return nil, err
	}
	var cds []*dns.CDS
	for _, rr := range rrs {
		if cd, ok := rr.(*dns.CDS); ok {
			cds = append(cds, cd)
		}
	}
	return cds, nil
}

// QueryDS returns the DS records for a zone (queried from the parent zone).
func (c *DNSClient) QueryDS(zone string) ([]*dns.DS, error) {
	rrs, err := c.query(zone, dns.TypeDS)
	if err != nil {
		return nil, err
	}
	var ds []*dns.DS
	for _, rr := range rrs {
		if d, ok := rr.(*dns.DS); ok {
			ds = append(ds, d)
		}
	}
	return ds, nil
}

// QueryDNSKEY returns the DNSKEY records for a zone without AD requirement.
func (c *DNSClient) QueryDNSKEY(zone string) ([]*dns.DNSKEY, error) {
	rrs, err := c.queryNoADCheck(zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	var keys []*dns.DNSKEY
	for _, rr := range rrs {
		if k, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// validateDNSSECChain validates zone keys via local DNSSEC chain verification
// (DS parent + DNSKEY + CDNSKEY/CDS signatures).
// Used as fallback when AD flag unavailable on authoritative server.
func (c *DNSClient) validateDNSSECChain(zone string) ([]plugin.KeyRecord, bool, error) {
	slog.Debug("DNSSEC fallback: attempting local chain validation", "zone", zone)

	// Step 1: Fetch DS from parent (AD required for trust anchor)
	parentDS, err := c.QueryDS(zone)
	if err != nil {
		return nil, false, fmt.Errorf("fetching parent DS: %w", err)
	}
	if len(parentDS) == 0 {
		return nil, false, fmt.Errorf("no DS records found for zone %s in parent", zone)
	}
	slog.Debug("DNSSEC fallback: fetched parent DS records", "zone", zone, "count", len(parentDS))

	// Step 2: Fetch DNSKEY from zone (no AD requirement)
	dnskeys, err := c.QueryDNSKEY(zone)
	if err != nil {
		return nil, false, fmt.Errorf("fetching DNSKEY: %w", err)
	}
	if len(dnskeys) == 0 {
		return nil, false, fmt.Errorf("no DNSKEY records found for zone %s", zone)
	}
	slog.Debug("DNSSEC fallback: fetched zone DNSKEY records", "zone", zone, "count", len(dnskeys))

	// Step 3: Verify that at least one KSK (flags=257) matches a parent DS
	var validKSK *dns.DNSKEY
	for _, key := range dnskeys {
		if key.Flags&257 == 257 { // KSK flag
			for _, ds := range parentDS {
				computedDigest := computeDSDigestFromDNSKEY(zone, key, ds.DigestType)
				if strings.EqualFold(computedDigest, ds.Digest) {
					validKSK = key
					slog.Debug("DNSSEC fallback: found KSK matching parent DS", "zone", zone, "key_tag", key.KeyTag(), "ds_digest_type", ds.DigestType)
					break
				}
			}
		}
		if validKSK != nil {
			break
		}
	}
	if validKSK == nil {
		return nil, false, fmt.Errorf("no DNSKEY KSK matches any parent DS for zone %s", zone)
	}

	// Step 4: Fetch CDNSKEY/CDS (no AD requirement) and verify
	cdnskeys, cdnskeyErr := c.queryCDNSKEYNoADCheck(zone)
	cdsRecords, cdsErr := c.queryCDSNoADCheck(zone)

	hasCDNSKEY := cdnskeyErr == nil && len(cdnskeys) > 0
	hasCDS := cdsErr == nil && len(cdsRecords) > 0

	if !hasCDNSKEY && !hasCDS {
		return nil, false, fmt.Errorf("no CDNSKEY or CDS found for zone %s", zone)
	}
	slog.Debug("DNSSEC fallback: fetched zone keys", "zone", zone, "has_cdnskey", hasCDNSKEY, "has_cds", hasCDS)

	// Check for sentinel (algorithm 0 = request DNSSEC removal)
	if hasCDS {
		for _, c := range cdsRecords {
			if c.Algorithm == 0 {
				slog.Info("DNSSEC fallback: zone requests DNSSEC removal (sentinel CDS)", "zone", zone)
				return nil, true, nil
			}
		}
	}
	if hasCDNSKEY {
		for _, k := range cdnskeys {
			if k.Algorithm == 0 {
				slog.Info("DNSSEC fallback: zone requests DNSSEC removal (sentinel CDNSKEY)", "zone", zone)
				return nil, true, nil
			}
		}
	}

	// Build result from CDNSKEY (or CDS if no CDNSKEY)
	if hasCDNSKEY {
		records := buildFromCDNSKEY(zone, cdnskeys, cdsRecords)
		if len(records) == 0 {
			return nil, false, fmt.Errorf("CDNSKEY records found but produced no valid key records (fallback chain validation) for zone %s", zone)
		}
		slog.Info("DNSSEC fallback: validation succeeded using local chain", "zone", zone, "method", "fallback_chain_validation")
		return records, false, nil
	}
	records := buildFromCDS(cdsRecords)
	if len(records) == 0 {
		return nil, false, fmt.Errorf("CDS records found but produced no valid key records (fallback chain validation) for zone %s", zone)
	}
	slog.Info("DNSSEC fallback: validation succeeded using local chain", "zone", zone, "method", "fallback_chain_validation")
	return records, false, nil
}

// FetchZoneKeys retrieves the desired DNSSEC keys for a zone, preferring
// CDNSKEY over CDS. Returns the key records and whether the zone requests
// DNSSEC removal (sentinel algorithm 0).
// Falls back to local DNSSEC chain validation if AD flag unavailable.
func (c *DNSClient) FetchZoneKeys(zone string) ([]plugin.KeyRecord, bool, error) {
	cdnskeys, cdnskeyErr := c.QueryCDNSKEY(zone)
	cdsRecords, cdsErr := c.QueryCDS(zone)

	hasCDNSKEY := cdnskeyErr == nil && len(cdnskeys) > 0
	hasCDS := cdsErr == nil && len(cdsRecords) > 0

	// If both failed, check if AD is the issue (eligible for fallback)
	if !hasCDNSKEY && !hasCDS {
		cdnskeyNoAD := strings.Contains(fmt.Sprintf("%v", cdnskeyErr), "AD flag not set")
		cdsNoAD := strings.Contains(fmt.Sprintf("%v", cdsErr), "AD flag not set")

		if cdnskeyNoAD || cdsNoAD {
			slog.Debug("AD validation unavailable; attempting DNSSEC fallback", "zone", zone)
			// Attempt fallback: local DNSSEC chain validation
			keys, isSentinel, fallbackErr := c.validateDNSSECChain(zone)
			if fallbackErr == nil {
				// Fallback succeeded
				slog.Info("DNSSEC validation via fallback chain", "zone", zone)
				return keys, isSentinel, nil
			}
			slog.Error("DNSSEC fallback chain validation failed", "zone", zone, "error", fallbackErr.Error())
			// Fallback failed; return fallback error (more informative than original AD error)
			return nil, false, fmt.Errorf("AD validation unavailable; local DNSSEC chain validation failed: %w", fallbackErr)
		}

		// Not AD-related; return original errors
		if cdnskeyErr != nil {
			return nil, false, fmt.Errorf("querying CDNSKEY: %w", cdnskeyErr)
		}
		if cdsErr != nil {
			return nil, false, fmt.Errorf("querying CDS: %w", cdsErr)
		}
		return nil, false, nil
	}

	slog.Debug("Direct AD validation succeeded", "zone", zone)

	// Check for sentinel (algorithm 0 = request DNSSEC removal)
	if hasCDS {
		for _, c := range cdsRecords {
			if c.Algorithm == 0 {
				return nil, true, nil
			}
		}
	}
	if hasCDNSKEY {
		for _, k := range cdnskeys {
			if k.Algorithm == 0 {
				return nil, true, nil
			}
		}
	}

	// Prefer CDNSKEY: build records from CDNSKEY, matching CDS if available
	if hasCDNSKEY {
		records := buildFromCDNSKEY(zone, cdnskeys, cdsRecords)
		if len(records) == 0 {
			return nil, false, fmt.Errorf("CDNSKEY records found but produced no valid key records for zone %s", zone)
		}
		return records, false, nil
	}

	// Only CDS available
	records := buildFromCDS(cdsRecords)
	if len(records) == 0 {
		return nil, false, fmt.Errorf("CDS records found but produced no valid key records for zone %s", zone)
	}
	return records, false, nil
}

// buildFromCDNSKEY builds KeyRecords from CDNSKEY, computing CDS if needed.
func buildFromCDNSKEY(zone string, keys []*dns.CDNSKEY, cdsRecords []*dns.CDS) []plugin.KeyRecord {
	// Index CDS by tag+algorithm for matching
	cdsMap := make(map[string]*dns.CDS)
	for _, c := range cdsRecords {
		key := fmt.Sprintf("%d/%d", c.KeyTag, c.Algorithm)
		cdsMap[key] = c
	}

	var records []plugin.KeyRecord
	for _, k := range keys {
		flags := k.Flags
		protocol := k.Protocol
		publicKey := k.PublicKey

		tag := k.KeyTag()

		// Try to find matching CDS
		cdsKey := fmt.Sprintf("%d/%d", tag, k.Algorithm)
		cds, hasCDS := cdsMap[cdsKey]

		var digestType uint8
		var digest string
		if hasCDS {
			digestType = cds.DigestType
			digest = cds.Digest
		} else {
			// Compute DS (SHA-256) from CDNSKEY
			digestType = dns.SHA256
			digest = computeDSDigest(zone, k, dns.SHA256)
		}

		records = append(records, plugin.KeyRecord{
			Tag:        tag,
			Algorithm:  k.Algorithm,
			DigestType: digestType,
			Digest:     digest,
			Flags:      &flags,
			Protocol:   &protocol,
			PublicKey:  &publicKey,
		})
	}
	return records
}

// buildFromCDS builds KeyRecords from CDS only (no CDNSKEY data).
func buildFromCDS(cdsRecords []*dns.CDS) []plugin.KeyRecord {
	var records []plugin.KeyRecord
	for _, c := range cdsRecords {
		records = append(records, plugin.KeyRecord{
			Tag:        c.KeyTag,
			Algorithm:  c.Algorithm,
			DigestType: c.DigestType,
			Digest:     c.Digest,
		})
	}
	return records
}

// computeDSDigest computes a DS digest from a CDNSKEY record.
func computeDSDigest(zone string, key *dns.CDNSKEY, digestType uint8) string {
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}

	// Build the DNSKEY wire format for hashing
	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     key.Flags,
		Protocol:  key.Protocol,
		Algorithm: key.Algorithm,
		PublicKey: key.PublicKey,
	}

	ds := dnskey.ToDS(digestType)
	if ds == nil {
		return ""
	}
	return ds.Digest
}

// computeDSDigestFromDNSKEY computes a DS digest from a DNSKEY record.
func computeDSDigestFromDNSKEY(zone string, key *dns.DNSKEY, digestType uint8) string {
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}

	// Build the DNSKEY wire format for hashing
	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     key.Flags,
		Protocol:  key.Protocol,
		Algorithm: key.Algorithm,
		PublicKey: key.PublicKey,
	}

	ds := dnskey.ToDS(digestType)
	if ds == nil {
		return ""
	}
	return ds.Digest
}

// CompareDS checks whether the current DS records match the desired keys.
// Returns lists of keys to add and remove.
func CompareDS(current []*dns.DS, desired []plugin.KeyRecord) (toAdd, toRemove []plugin.KeyRecord) {
	type dsID struct {
		Tag        uint16
		Algorithm  uint8
		DigestType uint8
		Digest     string
	}

	currentSet := make(map[dsID]bool)
	for _, d := range current {
		currentSet[dsID{d.KeyTag, d.Algorithm, d.DigestType, strings.ToUpper(d.Digest)}] = true
	}

	desiredSet := make(map[dsID]bool)
	for _, d := range desired {
		id := dsID{d.Tag, d.Algorithm, d.DigestType, strings.ToUpper(d.Digest)}
		desiredSet[id] = true
		if !currentSet[id] {
			toAdd = append(toAdd, d)
		}
	}

	for _, d := range current {
		id := dsID{d.KeyTag, d.Algorithm, d.DigestType, strings.ToUpper(d.Digest)}
		if !desiredSet[id] {
			toRemove = append(toRemove, plugin.KeyRecord{
				Tag:        d.KeyTag,
				Algorithm:  d.Algorithm,
				DigestType: d.DigestType,
				Digest:     d.Digest,
			})
		}
	}

	return toAdd, toRemove
}

// Unused but reserved for future digest computation without miekg/dns helpers.
var _ = sha256.New
var _ = hex.EncodeToString
