package core

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/core/helpers"
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

func (c *DNSClient) queryInternal(ctx context.Context, name string, qtype uint16, requireAD bool) ([]dns.RR, error) {
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

	var lastErr error
	for _, server := range c.servers {
		r, _, err := client.ExchangeContext(ctx, m, server)
		if err != nil {
			lastErr = err
			continue
		}
		if r.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("%s: rcode %s", server, dns.RcodeToString[r.Rcode])
			continue
		}
		if requireAD && !r.AuthenticatedData {
			lastErr = fmt.Errorf("%s: AD flag not set", server)
			continue
		}
		return r.Answer, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, fmt.Errorf("no valid response from any server for %s %s", name, dns.TypeToString[qtype])
}

func queryTyped[T dns.RR](c *DNSClient, ctx context.Context, zone string, qtype uint16, requireAD bool) ([]T, error) {
	rrs, err := c.queryInternal(ctx, zone, qtype, requireAD)
	if err != nil {
		return nil, err
	}
	return helpers.ExtractRR[T](rrs), nil
}

// QueryCDNSKEY returns the CDNSKEY records for a zone.
func (c *DNSClient) QueryCDNSKEY(ctx context.Context, zone string) ([]*dns.CDNSKEY, error) {
	return queryTyped[*dns.CDNSKEY](c, ctx, zone, dns.TypeCDNSKEY, true)
}

// queryCDNSKEYNoADCheck returns CDNSKEY records without AD requirement.
func (c *DNSClient) queryCDNSKEYNoADCheck(ctx context.Context, zone string) ([]*dns.CDNSKEY, error) {
	return queryTyped[*dns.CDNSKEY](c, ctx, zone, dns.TypeCDNSKEY, false)
}

// QueryCDS returns the CDS records for a zone.
func (c *DNSClient) QueryCDS(ctx context.Context, zone string) ([]*dns.CDS, error) {
	return queryTyped[*dns.CDS](c, ctx, zone, dns.TypeCDS, true)
}

// queryCDSNoADCheck returns CDS records without AD requirement.
func (c *DNSClient) queryCDSNoADCheck(ctx context.Context, zone string) ([]*dns.CDS, error) {
	return queryTyped[*dns.CDS](c, ctx, zone, dns.TypeCDS, false)
}

// QueryDS returns the DS records for a zone (queried from the parent zone).
func (c *DNSClient) QueryDS(ctx context.Context, zone string) ([]*dns.DS, error) {
	return queryTyped[*dns.DS](c, ctx, zone, dns.TypeDS, true)
}

// QueryDNSKEY returns the DNSKEY records for a zone without AD requirement.
func (c *DNSClient) QueryDNSKEY(ctx context.Context, zone string) ([]*dns.DNSKEY, error) {
	return queryTyped[*dns.DNSKEY](c, ctx, zone, dns.TypeDNSKEY, false)
}

// validateDNSSECChain validates zone keys via local DNSSEC chain verification
// (DS parent + DNSKEY + CDNSKEY/CDS signatures).
// Used as fallback when AD flag unavailable on authoritative server.
func (c *DNSClient) validateDNSSECChain(ctx context.Context, zone string) ([]plugin.KeyRecord, bool, error) {
	slog.Debug("DNSSEC fallback: attempting local chain validation", "zone", zone)

	// Step 1: Fetch DS from parent (AD required for trust anchor)
	parentDS, err := c.QueryDS(ctx, zone)
	if err != nil {
		return nil, false, fmt.Errorf("fetching parent DS: %w", err)
	}
	if len(parentDS) == 0 {
		return nil, false, fmt.Errorf("no DS records found for zone %s in parent", zone)
	}
	slog.Debug("DNSSEC fallback: fetched parent DS records", "zone", zone, "count", len(parentDS))

	// Step 2: Fetch DNSKEY from zone (no AD requirement)
	dnskeys, err := c.QueryDNSKEY(ctx, zone)
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
				computedDigest := dsDigest(zone, key.Flags, key.Protocol, key.Algorithm, key.PublicKey, ds.DigestType)
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
	cdnskeys, cdnskeyErr := c.queryCDNSKEYNoADCheck(ctx, zone)
	cdsRecords, cdsErr := c.queryCDSNoADCheck(ctx, zone)

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
				slog.Debug("DNSSEC fallback: zone requests DNSSEC removal (sentinel CDS)", "zone", zone)
				return nil, true, nil
			}
		}
	}
	if hasCDNSKEY {
		for _, k := range cdnskeys {
			if k.Algorithm == 0 {
				slog.Debug("DNSSEC fallback: zone requests DNSSEC removal (sentinel CDNSKEY)", "zone", zone)
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
		slog.Debug("DNSSEC fallback: validation succeeded using local chain", "zone", zone, "method", "fallback_chain_validation")
		return records, false, nil
	}
	records := buildFromCDS(cdsRecords)
	if len(records) == 0 {
		return nil, false, fmt.Errorf("CDS records found but produced no valid key records (fallback chain validation) for zone %s", zone)
	}
	slog.Debug("DNSSEC fallback: validation succeeded using local chain", "zone", zone, "method", "fallback_chain_validation")
	return records, false, nil
}

// FetchZoneKeys retrieves the desired DNSSEC keys for a zone, preferring
// CDNSKEY over CDS. Returns the key records and whether the zone requests
// DNSSEC removal (sentinel algorithm 0).
// Falls back to local DNSSEC chain validation if AD flag unavailable.
func (c *DNSClient) FetchZoneKeys(ctx context.Context, zone string) ([]plugin.KeyRecord, bool, error) {
	cdnskeys, cdnskeyErr := c.QueryCDNSKEY(ctx, zone)
	cdsRecords, cdsErr := c.QueryCDS(ctx, zone)

	hasCDNSKEY := cdnskeyErr == nil && len(cdnskeys) > 0
	hasCDS := cdsErr == nil && len(cdsRecords) > 0

	// If both failed, check if AD is the issue (eligible for fallback)
	if !hasCDNSKEY && !hasCDS {
		cdnskeyNoAD := strings.Contains(fmt.Sprintf("%v", cdnskeyErr), "AD flag not set")
		cdsNoAD := strings.Contains(fmt.Sprintf("%v", cdsErr), "AD flag not set")

		if cdnskeyNoAD || cdsNoAD {
			slog.Debug("AD validation unavailable; attempting DNSSEC fallback", "zone", zone)
			// Attempt fallback: local DNSSEC chain validation
			keys, isSentinel, fallbackErr := c.validateDNSSECChain(ctx, zone)
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
			digest = dsDigest(zone, k.Flags, k.Protocol, k.Algorithm, k.PublicKey, dns.SHA256)
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

// dsDigest computes a DS digest from DNSKEY fields.
func dsDigest(zone string, flags uint16, protocol uint8, algorithm uint8, publicKey string, digestType uint8) string {
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}

	// Build the DNSKEY wire format for hashing
	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET},
		Flags:     flags,
		Protocol:  protocol,
		Algorithm: algorithm,
		PublicKey: publicKey,
	}

	ds := dnskey.ToDS(digestType)
	if ds == nil {
		return ""
	}
	return ds.Digest
}
