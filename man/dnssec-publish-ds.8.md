%%%
title = "DNSSEC-PUBLISH-DS 8"
area = "dnssec-publish-ds"
workgroup = "System Administration Commands"
date = "2026-05-01T00:00:00Z"
%%%

# NAME

dnssec-publish-ds - DNSSEC DS record publisher daemon

# SYNOPSIS

**dnssec-publish-ds**
[**--config** *FILE*]
[**--log-level** *LEVEL*]
[**--skip-initial-jitter**]
[**--dump-config**]
[**--version**]

# DESCRIPTION

**dnssec-publish-ds** is a daemon that monitors CDS and CDNSKEY records for configured DNS zones
and automatically updates DS records at the registrar via provider plugins.

The daemon runs continuously, periodically checking each configured zone
for alignment between its CDS/CDNSKEY records and the published DS records.
When a mismatch is detected, the daemon submits an update to the provider
and polls until the operation completes.

CDNSKEY records are preferred over CDS when both are present.
DNS responses must be DNSSEC-validated (AD flag set).

# OPTIONS

**--config** *FILE*

:   Path to the TOML configuration file.
    Default: */etc/dnssec-publish-ds/config.toml*

**--log-level** *LEVEL*

:   Set the log level. Valid values: **debug**, **info**, **warn**, **error**.
    Overrides the value set in the configuration file.

**--skip-initial-jitter**

:   Bypass the initial randomised startup delay (up to 5 minutes).
    Useful for testing or when starting after a manual restart.

**--dump-config**

:   Print the fully resolved configuration (after merging conf.d/) as JSON to
    stdout and exit without starting the daemon.
    Useful to verify that secrets were loaded correctly.

**--version**

:   Print the version and exit.

**--help**

:   Print usage information and exit.

# CONFIGURATION

### **File format**

The configuration uses TOML format.
The main file is loaded first, then every **.toml** file inside a
**conf.d/** directory placed next to the main file is merged in
lexicographic order.
Because groups are a **map** (keyed by group name), conf.d files can
extend or override individual fields of an existing group without
repeating all its settings.

Environment variables with the prefix **DNSSEC\_PUBLISH\_DS\_** override
any configuration value.
The variable name is the key path in upper-case with dots and hyphens
replaced by underscores
(e.g., **DNSSEC_PUBLISH_DS_LOG_LEVEL=debug**).

### **Global settings**

**status_file** *string*

:   Path to the JSON file used to persist in-progress operation state across
    restarts.
    Default: */var/lib/dnssec-publish-ds/status.json*

**dns_timeout** *duration*

:   Timeout for each DNS query (e.g., **5s**, **2s**).
    Default: **5s**

**log_level** *string*

:   Log verbosity. One of **debug**, **info**, **warn**, **error**.
    Default: **info**

### **Group settings**

Each group is defined under **[group.**_name_**]** where _name_ is
an arbitrary identifier for the group.
Multiple groups can be declared in the same file or spread across conf.d
files; they are merged by name.

**plugin** *string* (required)

:   Name of the provider plugin to use (e.g., **ovh-v1**).

**check_interval** *duration*

:   How often the daemon checks zone alignment when idle.
    Default: **12h**

**error_retry_interval** *duration*

:   How long the daemon waits before retrying after a DNS or API error.
    Default: **5m**

**zones** *array of strings* (required)

:   List of DNS zone names managed by this group.
    Each zone must appear in at most one group.

**plugin_config** *table* (required)

:   Plugin-specific credentials and settings.
    See the **PLUGINS** section below.

### **Example: main file with one group**

```
status_file = "/var/lib/dnssec-publish-ds/status.json"
log_level   = "info"

[group.ovh-main]
plugin               = "ovh-v1"
check_interval       = "12h"
error_retry_interval = "5m"
zones                = ["example.com", "example.org"]

[plugins."ovh-v1"]
max_concurrency    = 1

[group.ovh-main.plugin_config]
endpoint           = "ovh-eu"
application_key    = "AK..."
application_secret = "AS..."
consumer_key       = "CK..."
```

### **Example: splitting groups and secrets across conf.d/**

```
# conf.d/10-groups.toml
[plugins."ovh-v1"]
max_concurrency = 1

[group.ovh-main]
plugin = "ovh-v1"
zones  = ["example.com"]

# conf.d/20-secrets.toml  (gitignored)
[group.ovh-main.plugin_config]
endpoint           = "ovh-eu"
application_key    = "AK..."
application_secret = "AS..."
consumer_key       = "CK..."
```

# PLUGINS

### **ovh-v1**

Manages DS records for domains registered at OVH via the OVH API v1.

Upon initialisation the plugin calls **GET /me** to verify that the
credentials are valid and logs the NIC handle of the authenticated account.

**plugin_config parameters:**

**endpoint** *string*

:   OVH API endpoint. Common values: **ovh-eu** (Europe), **ovh-ca**
    (Canada), **ovh-us** (United States).
    Default: **ovh-eu**

**application_key** *string* (required)

:   OVH application key.

**application_secret** *string* (required)

:   OVH application secret.

**consumer_key** *string* (required)

:   OVH consumer key (token bound to a specific NIC handle and set of
    permissions).

**allow_acceleration** *boolean*

:   Allow the daemon to call the acceleration endpoint to skip the 24-hour
    propagation wait when available.
    Default: **true**

**Global plugin parameters ([plugins."ovh-v1"]):**

**max_concurrency** *integer*

:   Global concurrency limit for OVH API calls shared by all **ovh-v1**
    instances in the process. Must be placed in the **[plugins."ovh-v1"]**
    section, not in a group's **plugin_config**.
    Default: **1**

**wait_submit** *duration*

:   Wait delay after submitting a DS update task.
    Must be placed in **[plugins."ovh-v1"]** (not in group plugin_config).
    Default: **30s**

**wait_poll_urgent** *duration*

:   Polling delay for urgent follow-up checks.
    Used when task is not accelerable or acceleration is allowed.
    Must be placed in **[plugins."ovh-v1"]** (not in group plugin_config).
    Default: **30s**

**wait_poll_passive** *duration*

:   Polling delay for non-urgent follow-up checks.
    Used when task is accelerable but **allow_acceleration** is disabled.
    When OVH returns **todoDate**, the daemon waits until
    **todoDate + wait_poll_passive** when this timestamp is in the future.
    If **todoDate** is missing or already in the past, it falls back to
    **wait_poll_passive**.
    Must be placed in **[plugins."ovh-v1"]** (not in group plugin_config).
    Default: **5m**

**OVH API routes required:**

| Method | Route |
|:-------|:------|
| GET | /me |
| GET | /domain/{zone}/task |
| GET | /domain/{zone}/dsRecord |
| GET | /domain/{zone}/dsRecord/{id} |
| POST | /domain/{zone}/dsRecord |
| GET | /domain/{zone}/task/{taskId} |
| POST | /domain/{zone}/task/{taskId}/accelerate |

**Operation flow:**

1. Submit: **POST /domain/{zone}/dsRecord** with the desired key set.

2. Accelerate: when **canAccelerate** is true and **allow_acceleration** is
   enabled, call **POST /domain/{zone}/task/{taskId}/accelerate**.

3. Wait: poll every **wait_poll_urgent** (default 30 s) in urgent paths, and
   every **wait_poll_passive** (default 5 m) when task is accelerable but
   acceleration is disabled. When available, **todoDate** is used to compute
   the next wake-up as **todoDate + wait_poll_passive**. Continue until status is **done**, **error**,
   **problem**, or **cancelled**.

### **rfc2136**

Manages DS records for any authoritative zone by sending DNS dynamic updates
(RFC 2136) directly to a primary name server.
The update is fully synchronous: the server immediately responds with a result
code, so no polling is required.

Before sending an update the plugin queries the target server for the current
DS records of the zone and recomputes the effective delta.
This ensures idempotency even when the target server differs from the
resolvers used by the core to detect changes.

Two authentication modes are supported, selected automatically based on
which sub-table is present in **plugin_config**:

**none**

:   No authentication. Access control is handled server-side (e.g., IP-based
    ACL in **named.conf** or **knot.conf**).

**tsig**

:   Transaction SIGnature (RFC 2845) using a shared HMAC secret.
    Enabled by the presence of **[plugin_config.tsig]**.

**plugin_config parameters:**

**server** *string* (required)

:   IP address or hostname of the primary name server that accepts dynamic
    updates for the zone.

**port** *integer*

:   UDP/TCP port of the name server.
    Default: **53**

**ttl** *integer*

:   TTL (in seconds) applied to newly added DS records.
    If absent, the plugin queries the target server for the zone SOA TTL.
    If the SOA query fails, **3600** is used.

**TSIG sub-table ([group.**_name_**.plugin_config.tsig]):**

**key_name** *string* (required)

:   TSIG key name (DNS FQDN, e.g., **update-key.**).

**secret** *string* (required)

:   Base64-encoded HMAC secret.

**algorithm** *string*

:   HMAC algorithm. One of **hmac-sha256.**, **hmac-sha512.**,
    **hmac-sha1.**, **hmac-md5.sig-alg.reg.int.**
    Default: **hmac-sha256.**

**Example - no authentication:**

```
[group.internal]
plugin = "rfc2136"
zones  = ["internal.example.com"]

[group.internal.plugin_config]
server = "192.168.1.1"
ttl    = 3600
```

**Example - TSIG:**

```
[group.internal]
plugin = "rfc2136"
zones  = ["internal.example.com"]

[group.internal.plugin_config]
server = "192.168.1.1"

[group.internal.plugin_config.tsig]
key_name  = "update-key."
secret    = "base64secret=="
algorithm = "hmac-sha256."
```

# FILES

*/etc/dnssec-publish-ds/config.toml*

:   Main configuration file.

*/etc/dnssec-publish-ds/conf.d/*

:   Supplementary configuration files loaded in lexicographic order and merged
    into the main configuration.

*/var/lib/dnssec-publish-ds/status.json*

:   Persistent state file. Records in-progress operations so that the daemon
    can resume after a restart without re-submitting already-pending tasks.

# SIGNALS

**SIGHUP**

:   Reload configuration. The daemon saves its current state, stops all
    zone runners, reloads the configuration, and restarts cleanly.

**SIGTERM**, **SIGINT**

:   Graceful shutdown. In-progress state is saved to the status file before
    exiting so that pending operations can be resumed on next start.

# EXIT STATUS

**0**

:   Normal termination.

**1**

:   Fatal error (invalid configuration, plugin initialisation failure, etc.).

# ENVIRONMENT

**DNSSEC_PUBLISH_DS_LOG_LEVEL**

:   Override **log_level**.

**DNSSEC_PUBLISH_DS_STATUS_FILE**

:   Override **status_file**.

**DNSSEC_PUBLISH_DS_DNS_TIMEOUT**

:   Override **dns_timeout**.

**DNSSEC\_PUBLISH\_DS\_**_GROUPNAME_**\_PLUGIN\_CONFIG\_APPLICATION\_KEY**

:   Override **application_key** for the named group, where *GROUPNAME* is
    the group name with hyphens replaced by underscores and converted to
    upper-case.
    Likewise for **APPLICATION\_SECRET**, **CONSUMER\_KEY**, and
    **ENDPOINT**.

# SEE ALSO

**systemctl**(1), **journalctl**(1)
