# xymon-ext-dnssec (Xymon Probe)

## Purpose

`xymon-ext-dnssec` is a Perl Xymon external probe that checks DNSSEC health for one or more zones and reports status/trends to Xymon.

It is focused on operational validation rather than registrar-side DS automation.

## What it checks

Per monitored zone, the probe validates:

- parent delegation discovery (NS + DS)
- DS to DNSKEY consistency
- DNSKEY/CDS/CDNSKEY presence and consistency
- RRSIG validity and expiration windows on key RRsets
- NS set coherence (parent vs zone)
- glue coherence for in-zone name servers
- NSEC3PARAM compliance checks
- key algorithm policy allow-list
- rollover timing heuristics (warning/error thresholds)

It also checks consistency of DNSKEY/CDS/CDNSKEY keytag sets across authoritative servers.

## Data sources

- recursive resolver(s) for parent discovery paths,
- authoritative server queries per NS (with optional TSIG),
- optional local cache for delegation and persistent per-zone state.

## RFC notes (probe-specific)

| RFC area | Status | Details |
|:--|:--|:--|
| NSEC3 operational recommendation (RFC 9276) | Implemented | Iteration and salt checks are enforced with warning/error semantics. |
| Algorithm naming policy (RFC 8624 mnemonics) | Implemented | Config supports names or numeric IDs. |
| TSIG transport auth (RFC 2845) | Implemented | Optional per-server credentials for authoritative queries. |
| Multi-signer style operational coherence | Partial | Cross-NS consistency checks exist; no full RFC 8901 protocol state machine. |

## Not covered / boundaries

- The probe does not publish DS records.
- It does not implement registrar APIs.
- It does not provide a complete root-to-leaf validating resolver implementation.
- It is designed for practical monitoring in Xymon, with configurable policy thresholds.

## Usage

```bash
perl xymon/server/ext/xymon-ext-dnssec --config /etc/xymon/xymon-ext-dnssec.yaml --zone example.com
```

Options include:

- `--zone` (repeatable)
- `--config`
- `--hosts-cfg`
- `--debug`
- `--debug-dns`

## Configuration highlights

Global keys:

- `test_name`
- `hosts_cfg`
- `resolver_timeout`
- `nameservers`
- `allowed_algorithms`
- `zone_warn_if_no_nsec3`
- `zone_require_permanent_cds_cdnskey`
- `zone_rrsig_delay`
- `zone_rollover_ds_propagation_delay`
- `server_options` (TSIG per server)
- `cache_file` / `cache_default_ttl`

## Example

```yaml
test_name: dnssec
resolver_timeout: 5
nameservers:
  - 9.9.9.9

allowed_algorithms:
  - ECDSAP256SHA256
  - ECDSAP384SHA384
  - ED25519
  - ED448

zone_warn_if_no_nsec3: true
zone_require_permanent_cds_cdnskey: true
zone_rrsig_delay: 5d:1d
zone_rollover_ds_propagation_delay: 7d:15d

server_options:
  default:
    tsig:
      name: xymon-key.
      algorithm: hmac-sha256
      secret: "base64secret=="
```
