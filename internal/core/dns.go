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

// queryTypedAD sends a DNS query requiring the AD (Authenticated Data) flag
// and returns records of type T extracted from the response.
func queryTypedAD[T dns.RR](c *DNSClient, ctx context.Context, zone string, qtype uint16) ([]T, error) {
	rrs, err := c.queryInternal(ctx, zone, qtype, true)
	if err != nil {
		return nil, err
	}
	return helpers.ExtractRR[T](rrs), nil
}

// queryTypedVerified sends a DNS query without AD requirement and cryptographically
// verifies that at least one RRSIG in the response validates the rrset against
// one of the provided DNSKEY records and parent DS. Only valid for KSK signed records.
// Special case: if keys is empty and qtype is DNSKEY, performs self-validation
// using the DNSKEY records from the rrset itself.
// Returns (nil, nil) when no records of the requested type are found.
func queryTypedVerified[T dns.RR](c *DNSClient, ctx context.Context, zone string, qtype uint16, keys []*dns.DNSKEY, parentDS []*dns.DS) ([]T, error) {
	raw, err := c.queryInternal(ctx, zone, qtype, false)
	if err != nil {
		return nil, err
	}
	records := helpers.ExtractRR[T](raw)
	if len(records) == 0 {
		return nil, nil
	}
	rrsigs := helpers.ExtractRR[*dns.RRSIG](raw)
	if len(rrsigs) == 0 {
		return nil, fmt.Errorf("no RRSIG records present for %s", dns.TypeToString[qtype])
	}
	rrset := make([]dns.RR, len(records))
	for i, r := range records {
		rrset[i] = r
	}

	// Special case: DNSKEY self-validation when keys is empty
	validationKeys := keys
	if qtype == dns.TypeDNSKEY && len(keys) == 0 {
		validationKeys = helpers.ExtractRR[*dns.DNSKEY](raw)
	}

	var lastErr error
	for _, rrsig := range rrsigs {
		for _, key := range validationKeys {
			for _, ds := range parentDS {
				if key.Flags&257 == 257 && ds.KeyTag == key.KeyTag() && key.KeyTag() == rrsig.KeyTag {
					// On valide d'abord que la clé correspond au DS parent
					computedDigest := dsDigest(zone, key.Flags, key.Protocol, key.Algorithm, key.PublicKey, ds.DigestType)
					if !strings.EqualFold(computedDigest, ds.Digest) {
						lastErr = fmt.Errorf("DNSKEY keytag %d does not match parent DS digest", key.KeyTag())
						continue
					}
					if !rrsig.ValidityPeriod(time.Now()) {
						lastErr = fmt.Errorf("RRSIG keytag %d expired or not yet valid", rrsig.KeyTag)
						continue
					}
					if err := rrsig.Verify(key, rrset); err == nil {
						return records, nil
					} else {
						lastErr = err
					}
				}
			}
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no DNSKEY matched any RRSIG keytag for %s", dns.TypeToString[qtype])
}

// QueryCDNSKEY returns the CDNSKEY records for a zone (requires AD flag).
func (c *DNSClient) QueryCDNSKEY(ctx context.Context, zone string) ([]*dns.CDNSKEY, error) {
	return queryTypedAD[*dns.CDNSKEY](c, ctx, zone, dns.TypeCDNSKEY)
}

// queryCDNSKEYNoADCheck returns CDNSKEY records without AD requirement,
// verifying their RRSIG against the provided DNSKEY trust anchors.
func (c *DNSClient) queryCDNSKEYNoADCheck(ctx context.Context, zone string, keys []*dns.DNSKEY, parentDS []*dns.DS) ([]*dns.CDNSKEY, error) {
	return queryTypedVerified[*dns.CDNSKEY](c, ctx, zone, dns.TypeCDNSKEY, keys, parentDS)
}

// QueryCDS returns the CDS records for a zone (requires AD flag).
func (c *DNSClient) QueryCDS(ctx context.Context, zone string) ([]*dns.CDS, error) {
	return queryTypedAD[*dns.CDS](c, ctx, zone, dns.TypeCDS)
}

// queryCDSNoADCheck returns CDS records without AD requirement,
// verifying their RRSIG against the provided DNSKEY trust anchors.
func (c *DNSClient) queryCDSNoADCheck(ctx context.Context, zone string, keys []*dns.DNSKEY, parentDS []*dns.DS) ([]*dns.CDS, error) {
	return queryTypedVerified[*dns.CDS](c, ctx, zone, dns.TypeCDS, keys, parentDS)
}

// QueryDS returns the DS records for a zone (requires AD flag).
func (c *DNSClient) QueryDS(ctx context.Context, zone string) ([]*dns.DS, error) {
	return queryTypedAD[*dns.DS](c, ctx, zone, dns.TypeDS)
}

// QueryDNSKEYNoADCheck returns the DNSKEY records for a zone without AD requirement.
func (c *DNSClient) QueryDNSKEYNoADCheck(ctx context.Context, zone string, parentDS []*dns.DS) ([]*dns.DNSKEY, error) {
	// use self signed keys to auto validate,
	// l'appelant doit vérifier
	return queryTypedVerified[*dns.DNSKEY](c, ctx, zone, dns.TypeDNSKEY, nil, parentDS)
}

// validateDNSSECChain validates zone keys via local DNSSEC chain verification
// (DS parent + DNSKEY + CDNSKEY/CDS). Used as fallback when AD flag unavailable.
// Full chain: DS→KSK, RRSIG(DNSKEY) verified by KSK, RRSIG(CDNSKEY/CDS) verified by DNSKEY rrset.
// Returns the key records (including sentinel records if any); sentinel detection
// is left to the caller.
func (c *DNSClient) validateDNSSECChain(ctx context.Context, zone string) ([]*dns.CDNSKEY, []*dns.CDS, error) {
	slog.Debug("DNSSEC fallback: attempting local chain validation", "zone", zone)

	// Step 1: Fetch DS from parent (AD required for trust anchor)
	parentDS, err := c.QueryDS(ctx, zone)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching parent DS: %w", err)
	}
	if len(parentDS) == 0 {
		return nil, nil, fmt.Errorf("no DS records found for zone %s in parent", zone)
	}
	slog.Debug("DNSSEC fallback: fetched parent DS records", "zone", zone, "count", len(parentDS))

	// Step 2: Fetch DNSKEY from zone (no AD requirement)
	dnskeys, err := c.QueryDNSKEYNoADCheck(ctx, zone, parentDS)
	if err != nil {
		return nil, nil, fmt.Errorf("fetching DNSKEY: %w", err)
	}
	if len(dnskeys) == 0 {
		return nil, nil, fmt.Errorf("no DNSKEY records found for zone %s", zone)
	}
	slog.Debug("DNSSEC fallback: fetched zone DNSKEY records", "zone", zone, "count", len(dnskeys))

	// Step 4: Fetch CDNSKEY/CDS (no AD requirement) and verify
	cdnskeys, cdnskeyErr := c.queryCDNSKEYNoADCheck(ctx, zone, dnskeys, parentDS)
	cdsRecords, cdsErr := c.queryCDSNoADCheck(ctx, zone, dnskeys, parentDS)

	if cdnskeyErr != nil {
		return nil, nil, fmt.Errorf("DNSSEC fallback: querying CDNSKEY: %w", cdnskeyErr)
	}
	if cdsErr != nil {
		return nil, nil, fmt.Errorf("DNSSEC fallback:querying CDS: %w", cdsErr)
	}

	if (len(cdnskeys) + len(cdsRecords)) <= 0 {
		return nil, nil, fmt.Errorf("no CDNSKEY or CDS found for zone %s", zone)
	}
	slog.Debug("DNSSEC fallback: fetched zone keys", "zone", zone, "cdnskey", len(cdnskeys), "cds", len(cdsRecords))

	return cdnskeys, cdsRecords, nil
}

// FetchZoneKeys retrieves the desired DNSSEC keys for a zone, preferring
// CDNSKEY over CDS. Returns the key records and whether the zone requests
// DNSSEC removal (sentinel algorithm 0).
// Falls back to local DNSSEC chain validation if AD flag unavailable.
func (c *DNSClient) FetchZoneKeys(ctx context.Context, zone string) ([]plugin.KeyRecord, bool, error) {
	cdnskeys, cdnskeyErr := c.QueryCDNSKEY(ctx, zone)
	cdsRecords, cdsErr := c.QueryCDS(ctx, zone)

	cdnskeyNoAD := strings.Contains(fmt.Sprintf("%v", cdnskeyErr), "AD flag not set")
	cdsNoAD := strings.Contains(fmt.Sprintf("%v", cdsErr), "AD flag not set")

	// If both failed, check if AD is the issue (eligible for fallback)
	if cdnskeyNoAD || cdsNoAD {
		slog.Debug("AD validation unavailable; attempting DNSSEC fallback", "zone", zone)
		var fallbackErr error
		cdnskeys, cdsRecords, fallbackErr = c.validateDNSSECChain(ctx, zone)
		if fallbackErr != nil {
			slog.Error("DNSSEC fallback chain validation failed", "zone", zone, "error", fallbackErr.Error())
			return nil, false, fmt.Errorf("AD validation unavailable; local DNSSEC chain validation failed: %w", fallbackErr)
		}
		slog.Info("DNSSEC validation via fallback chain", "zone", zone)
	} else {
		// Not AD-related; return original errors
		if cdnskeyErr != nil {
			return nil, false, fmt.Errorf("querying CDNSKEY: %w", cdnskeyErr)
		}
		if cdsErr != nil {
			return nil, false, fmt.Errorf("querying CDS: %w", cdsErr)
		}
		slog.Debug("Direct AD validation succeeded", "zone", zone)
	}
	cdnskeyKeyRecords := buildFromCDNSKEY(zone, cdnskeys)
	cdsKeyRecords := buildFromCDS(cdsRecords)

	records, mergeErr := mergeKeyRecords(cdnskeyKeyRecords, cdsKeyRecords)
	if mergeErr != nil {
		return nil, false, fmt.Errorf("incoherent CDNSKEY/CDS records for zone %s: %w", zone, mergeErr)
	}

	// Sentinel detection (algorithm 0 = request DNSSEC removal)
	for _, r := range records {
		if r.Algorithm == 0 {
			return nil, true, nil
		}
	}
	return records, false, nil
}

// buildFromCDNSKEY builds KeyRecords from CDNSKEY.
func buildFromCDNSKEY(zone string, keys []*dns.CDNSKEY) []plugin.KeyRecord {
	var records []plugin.KeyRecord
	for _, k := range keys {
		flags := k.Flags
		protocol := k.Protocol
		publicKey := k.PublicKey

		tag := k.KeyTag()

		digestType := dns.SHA256 // TODO: voir pour variabiliser en fonction du parent
		digest := dsDigest(zone, k.Flags, k.Protocol, k.Algorithm, k.PublicKey, digestType)

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

// mergeKeyRecords fuses CDNSKEY records (rich: key material present) with CDS
// records. For a given KeyTag, the DigestType and Digest from the CDS are
// preferred over the locally computed SHA-256 digest, since the server-side CDS
// carries the canonical hash algorithm chosen by the operator.
//
// If both slices are non-empty, the sets of KeyTags must be identical
// (same tags, same count), otherwise an error is returned.
// If only one slice is non-empty, it is returned as-is.
func mergeKeyRecords(cdnskeyRecords, cdsRecords []plugin.KeyRecord) ([]plugin.KeyRecord, error) {
	if len(cdnskeyRecords) != len(cdsRecords) {
		return nil, fmt.Errorf("CDNSKEY has %d entries but CDS has %d distinct keytags",
			len(cdnskeyRecords), len(cdsRecords))
	}

	if len(cdsRecords) == 0 {
		return cdnskeyRecords, nil
	}
	if len(cdnskeyRecords) == 0 {
		return cdsRecords, nil
	}

	// Index CDS by keytag (one entry per keytag expected).
	cdsIndex := make(map[uint16]plugin.KeyRecord, len(cdsRecords))
	for _, r := range cdsRecords {
		cdsIndex[r.Tag] = r
	}

	merged := make([]plugin.KeyRecord, len(cdnskeyRecords))
	for i, r := range cdnskeyRecords {
		cds, ok := cdsIndex[r.Tag]
		if !ok {
			return nil, fmt.Errorf("CDNSKEY keytag %d has no matching CDS record", r.Tag)
		}
		merged[i] = r
		merged[i].DigestType = cds.DigestType
		merged[i].Digest = cds.Digest
	}
	return merged, nil
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
