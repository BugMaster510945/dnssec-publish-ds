# dnssec-publish-ds (Daemon)

## Purpose

`dnssec-publish-ds` is a long-running daemon that:

- reads CDS and CDNSKEY from child zones,
- compares with current parent DS,
- submits DS updates through provider plugins,
- resumes in-progress operations across restarts.

## Runtime flow

1. Load merged config (main TOML + optional conf.d).
2. Initialize one global plugin object per plugin type.
3. Initialize one group plugin instance per group.
4. Start one zone runner goroutine per zone.
5. For each zone:
   - fetch desired key data from DNS,
   - compute add/remove DS delta,
   - execute/update provider workflow,
   - persist state when workflow is asynchronous.
6. Handle signals:
   - `SIGHUP`: reload config (logical restart)
   - `SIGTERM`/`SIGINT`: graceful shutdown with status save

## Plugin model

Global plugin interface:

- `Init(globalConfig, logger)`
- `NewGroup(groupName, groupConfig)`

Group plugin interface:

- `Update(ctx, req) -> UpdateResult`

`UpdateResult` supports asynchronous flows through:

- `InProgress` boolean,
- `Raw` opaque provider state,
- `NextWait` polling delay hint.

## Providers

## ovh-v1

- Uses OVH API (`/me`, `/domain/{zone}/dsRecord`, task polling, optional accelerate).
- Requires credentials in group `plugin_config`.
- Supports global plugin-level throttling and wait policy.
- Requires CDNSKEY-capable desired records.

## rfc2136

- Sends DNS UPDATE directly to authoritative server.
- Supports auth modes:
  - none
  - TSIG (shared secret)
- No polling state machine required (synchronous response).
- SIG(0) is currently not implemented.

## RFC notes (daemon-specific)

| RFC area | Status | Details |
|:--|:--|:--|
| RFC 2136 dynamic update | Implemented | Via `rfc2136` provider. |
| RFC 2845 TSIG | Implemented | Optional for `rfc2136`. |
| RFC 2931 SIG(0) | Not implemented | Explicitly rejected in config. |
| CDS/CDNSKEY-driven DS alignment | Partial | Implemented operationally; strict coherence behavior applies. |

## Important behavioral limits

- Sentinel removal request (algorithm `0`) is logged and skipped.
- AD flag is required by daemon DNS lookups for CDS/CDNSKEY/DS path.
- Current merge behavior is strict for CDS/CDNSKEY coherence.
- No root-trust-anchor validating resolver is embedded in daemon.

## Config essentials

Global keys:

- `status_file`
- `dns_timeout`
- `log_level`
- `plugins.<name>.*` (plugin-global)

Group keys:

- `plugin`
- `check_interval`
- `error_retry_interval`
- `zones`
- `plugin_config`

## Example (OVH)

```toml
status_file = "/var/lib/dnssec-publish-ds/status.json"
log_level = "info"

[plugins."ovh-v1"]
max_concurrency = 1
wait_submit = "30s"
wait_poll_urgent = "30s"
wait_poll_passive = "5m"

[group.ovh-main]
plugin = "ovh-v1"
zones = ["example.com"]

[group.ovh-main.plugin_config]
endpoint = "ovh-eu"
application_key = "AK..."
application_secret = "AS..."
consumer_key = "CK..."
allow_acceleration = true
```

## Example (RFC2136 + TSIG)

```toml
[group.internal]
plugin = "rfc2136"
zones = ["example.com"]

[group.internal.plugin_config]
server = "192.0.2.53"
port = 53
ttl = 3600

[group.internal.plugin_config.tsig]
key_name = "update-key."
secret = "base64secret=="
algorithm = "hmac-sha256."
```

## Build and run

```bash
go test ./...
go build -o dnssec-publish-ds .
./dnssec-publish-ds --config /etc/dnssec-publish-ds/config.toml
```
