package core

import (
	"context"
	"fmt"
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

// QueryCDNSKEY returns the CDNSKEY records for a zone (requires AD flag).
func (c *DNSClient) QueryCDNSKEY(ctx context.Context, zone string) ([]*dns.CDNSKEY, error) {
	return queryTypedAD[*dns.CDNSKEY](c, ctx, zone, dns.TypeCDNSKEY)
}

// QueryCDS returns the CDS records for a zone (requires AD flag).
func (c *DNSClient) QueryCDS(ctx context.Context, zone string) ([]*dns.CDS, error) {
	return queryTypedAD[*dns.CDS](c, ctx, zone, dns.TypeCDS)
}

// QueryDS returns the DS records for a zone (requires AD flag).
func (c *DNSClient) QueryDS(ctx context.Context, zone string) ([]*dns.DS, error) {
	return queryTypedAD[*dns.DS](c, ctx, zone, dns.TypeDS)
}

// FetchZoneKeys retrieves the desired DNSSEC keys for a zone, preferring
// CDNSKEY over CDS. Returns the key records and whether the zone requests
// DNSSEC removal (sentinel algorithm 0).
// Falls back to local DNSSEC chain validation if AD flag unavailable.
func (c *DNSClient) FetchZoneKeys(ctx context.Context, zone string) ([]plugin.KeyRecord, bool, error) {
	cdnskeys, cdnskeyErr := c.QueryCDNSKEY(ctx, zone)
	cdsRecords, cdsErr := c.QueryCDS(ctx, zone)

	if cdnskeyErr != nil {
		return nil, false, fmt.Errorf("querying CDNSKEY: %w", cdnskeyErr)
	}
	if cdsErr != nil {
		return nil, false, fmt.Errorf("querying CDS: %w", cdsErr)
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
