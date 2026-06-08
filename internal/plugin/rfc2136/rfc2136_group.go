package rfc2136

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/core/helpers"
	"gitlab.syshawk.com/planchon/dnssec-publish-ds/internal/plugin"
)

func (g *RFC2136Group) Name() string { return pluginName }

func (g *RFC2136Group) Capabilities() plugin.Capabilities {
	return plugin.Capabilities{RequiresCDNSKEY: false}
}

func (g *RFC2136Group) Update(ctx context.Context, req plugin.UpdateRequest) (plugin.UpdateResult, error) {
	zone := dns.Fqdn(req.Zone)

	// Step 1: query current DS records on the target server.
	currentDS, err := g.queryCurrentDS(ctx, zone)
	if err != nil {
		return plugin.UpdateResult{}, fmt.Errorf("%s: querying current DS for %s: %w", pluginName, zone, err)
	}

	// Step 2: compute the delta; bail out early if nothing to do.
	toAdd, toRemove := filterDelta(currentDS, req)
	if len(toAdd) == 0 && len(toRemove) == 0 {
		g.logger().Info("rfc2136: zone already up to date, skipping update", "zone", zone)
		return plugin.UpdateResult{}, nil
	}

	// Step 3: determine the authoritative parent zone and TTL via a SOA query.
	parent, ttl, err := g.resolveParentSOA(ctx, zone)
	if err != nil {
		return plugin.UpdateResult{}, fmt.Errorf("%s: resolving parent zone for %s: %w", pluginName, zone, err)
	}

	g.logger().Info("rfc2136: updating DS records",
		"zone", zone,
		"parent_zone", parent,
		"to_add", len(toAdd),
		"to_remove", len(toRemove),
	)

	// Step 4: build the DNS UPDATE message targeting the parent zone.
	// The RR owner names still use the child zone FQDN (correct for DS records).
	msg := new(dns.Msg)
	msg.SetUpdate(parent)

	if len(toAdd) > 0 {
		rrs := make([]dns.RR, 0, len(toAdd))
		for _, kr := range toAdd {
			rrs = append(rrs, keyRecordToDS(kr, zone, ttl))
		}
		msg.Insert(rrs)
	}

	if len(toRemove) > 0 {
		rrs := make([]dns.RR, 0, len(toRemove))
		for _, kr := range toRemove {
			// TTL is overridden to 0 by dns.Msg.Remove; pass 0 explicitly.
			rrs = append(rrs, keyRecordToDS(kr, zone, 0))
		}
		msg.Remove(rrs)
	}

	// Step 5: send the UPDATE (auth applied by exchange).
	resp, err := g.exchange(ctx, msg)
	if err != nil {
		return plugin.UpdateResult{}, fmt.Errorf("%s: sending UPDATE for %s: %w", pluginName, zone, err)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return plugin.UpdateResult{}, fmt.Errorf(
			"%s: UPDATE for %s rejected by server: %s",
			pluginName, zone, dns.RcodeToString[resp.Rcode],
		)
	}

	g.logger().Info("rfc2136: DS update successful", "zone", zone)
	return plugin.UpdateResult{}, nil
}

// exchange applies authentication (TSIG if configured), sends msg to g.addr and
// returns the response. All outgoing DNS messages must go through this method.
func (g *RFC2136Group) exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if g.auth.mode == authTSIG {
		msg.SetTsig(g.auth.tsig.keyName, g.auth.tsig.algorithm, 300, time.Now().Unix())
	}
	resp, _, err := g.client.ExchangeContext(ctx, msg, g.addr)
	return resp, err
}

// queryCurrentDS queries the target authoritative server for the current DS
// records of the zone.
func (g *RFC2136Group) queryCurrentDS(ctx context.Context, zone string) ([]*dns.DS, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(zone, dns.TypeDS)
	msg.RecursionDesired = false

	resp, err := g.exchange(ctx, msg)
	if err != nil {
		return nil, err
	}
	return helpers.ExtractRR[*dns.DS](resp.Answer), nil
}

// resolveParentSOA queries the target server for the SOA of parentZone(zone)
// (zone with its leftmost label stripped). The server returns the SOA either
// in the ANSWER section (if it owns that exact zone) or in the AUTHORITY
// section (for a higher-level authoritative zone). The SOA owner name is the
// zone to target in the DNS UPDATE, and its Minttl is used as the DS TTL
// (unless overridden by g.ttl).
func (g *RFC2136Group) resolveParentSOA(ctx context.Context, zone string) (parent string, ttl uint32, err error) {
	candidate := parentZone(zone)
	msg := new(dns.Msg)
	msg.SetQuestion(candidate, dns.TypeSOA)
	msg.RecursionDesired = false

	resp, err := g.exchange(ctx, msg)
	if err != nil {
		return "", 0, fmt.Errorf("SOA query for %s: %w", candidate, err)
	}

	for _, rr := range append(resp.Answer, resp.Ns...) {
		if soa, ok := rr.(*dns.SOA); ok {
			ttl := soa.Minttl
			if g.ttl != nil {
				ttl = *g.ttl
			}
			g.logger().Debug("rfc2136: resolved authoritative parent zone via SOA",
				"zone", zone, "parent", soa.Hdr.Name, "ttl", ttl)
			return soa.Hdr.Name, ttl, nil
		}
	}

	return "", 0, fmt.Errorf("no SOA found for %s", candidate)
}

// parentZone returns the immediate parent of an FQDN by stripping the leftmost label.
// Examples: "example.fr." -> "fr.", "sub.example.com." -> "example.com.", "fr." -> "."
func parentZone(zone string) string {
	idx := strings.Index(zone, ".")
	if idx < 0 || idx == len(zone)-1 {
		return "."
	}
	return zone[idx+1:]
}

// filterDelta filters the engine's delta against the server's actual state:
// add only records absent from the server, remove only records present on it.
func filterDelta(current []*dns.DS, req plugin.UpdateRequest) ([]plugin.KeyRecord, []plugin.KeyRecord) {
	inServer := make(map[plugin.KeyRecord]bool, len(current))
	for _, ds := range current {
		inServer[helpers.KeyRecordFromDS(ds)] = true
	}
	var add, remove []plugin.KeyRecord
	for _, kr := range req.ToAdd {
		if !inServer[helpers.NormKeyRecord(kr)] {
			add = append(add, kr)
		}
	}
	for _, kr := range req.ToRemove {
		if inServer[helpers.NormKeyRecord(kr)] {
			remove = append(remove, kr)
		}
	}
	return add, remove
}

// keyRecordToDS converts a plugin.KeyRecord to a *dns.DS resource record.
func keyRecordToDS(kr plugin.KeyRecord, zone string, ttl uint32) *dns.DS {
	return &dns.DS{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeDS,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		KeyTag:     kr.Tag,
		Algorithm:  kr.Algorithm,
		DigestType: kr.DigestType,
		Digest:     strings.ToUpper(kr.Digest),
	}
}
