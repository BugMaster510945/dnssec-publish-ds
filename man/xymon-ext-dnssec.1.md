%%%
title = "XYMON-EXT-DNSSEC 1"
area = "xymon-ext-dnssec"
workgroup = "User Commands"
date = "2026-05-01T00:00:00Z"
%%%

# NAME

xymon-ext-dnssec - Xymon DNSSEC monitoring probe

# SYNOPSIS

**xymon-ext-dnssec**
[**--config** *FILE*]
[**--hosts-cfg** *FILE*]
[**--zone** *ZONE*]...
[**--debug**]
[**--debug-dns**]

# DESCRIPTION

**xymon-ext-dnssec** is a Xymon external probe that checks the DNSSEC health of one or more DNS
zones and reports the result to the Xymon monitoring server.

For each zone, the probe:

* Queries the parent zone to retrieve the DS delegation and NS list.

* For each authoritative name server: verifies the DNSKEY->DS chain,
  RRSIG validity and expiry on DNSKEY, SOA, NS, CDS, CDNSKEY and NSEC3PARAM
  RRsets, checks NSEC3PARAM RFC 9276 compliance, verifies that CDS/CDNSKEY
  matches the published DS records, and checks glue coherence.

Zones to monitor are read from the Xymon *hosts.cfg* file (via **xymongrep**(1))
and/or from the **--zone** command-line option.

# OPTIONS

**--zone** *ZONE*

:   Add *ZONE* to the list of zones to check.
    May be specified multiple times.
    Zones specified on the command line are merged with those found in *hosts.cfg*.

**--config** *FILE*

:   Path to the YAML configuration file.
    Default: */etc/xymon/xymon-ext-dnssec.yaml*

**--hosts-cfg** *FILE*

:   Path to the Xymon *hosts.cfg* file.
    Overrides both the **hosts_cfg** configuration key and the
    **HOSTSCFG** environment variable.

**--debug**

:   Enable verbose output: print all intermediate check results, not only
    failures.
    Use **--no-debug** to explicitly disable (default).

**--debug-dns**

:   Enable **Net::DNS**(3pm) wire-level debug output.
    Use **--no-debug-dns** to explicitly disable (default).

**--cache-file** *FILE*

:   Path to the on-disk cache file for parent delegation data. Value "-" disables
    the cache. If a relative path is provided it is resolved under the directory
    given by the environment variable **XYMONTMP** or, if absent, **TMP**. The
    probe does not create missing directories for relative paths.

**--cache-default-ttl** *SECONDS*

:   Default TTL (in seconds) to use when the computed delegation min-TTL cannot
    be determined. Default: **3600**.

# CONFIGURATION FILE

The probe reads a YAML configuration file (default:
*/etc/xymon/xymon-ext-dnssec.yaml*).
All keys are optional; built-in defaults apply when a key is absent.

### **Global settings**

**test_name** *STRING*

:   Name of the Xymon test column.
    Default: **dnssec**

**hosts_cfg** *PATH*

:   Path to the Xymon *hosts.cfg* file.
    Overridden by the **HOSTSCFG** environment variable or the
    **--hosts-cfg** CLI option.
    Default: (empty - relies on the environment variable set by Xymon)

**cache_file** *PATH*

:   Path to the on-disk cache file used to store parent delegation data. Use
    "-" to disable the cache. Relative paths are resolved under **XYMONTMP** or
    **TMP**; the probe does not create directories for relative paths.
    Default: **xymon-ext-dnssec.cache**

**cache_default_ttl** *SECONDS*

:   Fallback TTL (seconds) used when the probe cannot compute a min-TTL from
    parent delegation records. Default: **3600**

**resolver_timeout** *SECONDS*

:   UDP/TCP timeout for DNS queries (integer).
    Default: **5**

**nameservers** *LIST*

:   List of recursive resolver IP addresses to use for DNSSEC-validating queries.
    When empty, the system resolver is used.
    Default: **[]**

```
nameservers:
  - 9.9.9.9
  - 149.112.112.112
```

### **Algorithm policy**

**allowed_algorithms** *LIST*

:   List of DNSSEC algorithm names or numbers considered acceptable.
    Algorithm names follow RFC 8624 mnemonics (e.g. **ECDSAP256SHA256**).
    Numeric identifiers are also accepted.
    KSK, CDS, and CDNSKEY records using an algorithm absent from this list are
    flagged as yellow.

Default:

```
allowed_algorithms:
  - RSASHA256
  - RSASHA512
  - ECDSAP256SHA256
  - ECDSAP384SHA384
  - ED25519
  - ED448
```

### **Per-zone defaults**

These keys set the default behaviour for all zones.
They can be overridden on a per-zone basis in *hosts.cfg*
(see **HOSTS.CFG OPTIONS** below).

**zone_warn_if_no_nsec3** *BOOLEAN*

:   Emit a yellow status when a zone publishes no NSEC3PARAM record.
    Default: **true**

**zone_require_permanent_cds_cdnskey** *BOOLEAN*

:   Emit a yellow status when a zone publishes neither CDS nor CDNSKEY.
    Set to **false** for zones that only publish CDS/CDNSKEY during key rollovers.
    Default: **true**

**zone_parent_strip_labels** *INTEGER*

:   Number of leftmost DNS labels to strip from the zone name to derive the
    parent zone used for DS/NS delegation queries.
    For a standard second-level zone such as *example.com* the default value of
    **1** is correct (strips *example*, leaving *com*).
    For a zone hosted two levels below its Xymon-managed parent (e.g.
    *foo.bar.example.com* where *example.com* is already monitored)
    set this to **2** to reach *example.com* instead of *bar.example.com*.
    Default: **1**

**zone_rrsig_delay** *WARN*:*RED*

:   Default RRSIG renewal thresholds, applied on the valid signature with the
    farthest expiration date for each RRset.
    If remaining validity is below *WARN*, the probe emits yellow.
    If remaining validity is below *RED*, the probe emits red.
    Partial values are supported:
    * **36:24** means warn=36s, red=24s
    * **36** means warn=36s, red unchanged
    * **:24** means warn unchanged, red=24s
    Duration suffixes: **s**, **m**, **h**, **d**.
    Default: **5d:1d**

**zone_rollover_ds_propagation_delay** *WARN*:*RED*

:   Default thresholds for DS update/propagation delay during rollover
    transitions (for temporal DS/CDS/CDNSKEY consistency checks).
    If age is above *WARN*, the probe emits yellow.
    If age is above *RED*, the probe emits red.
    Format and partial values are identical to **zone_rrsig_delay**.
    Default: **7d:15d**

### **Per-server options**

**server_options** *MAP*

:   A map of authoritative server hostnames (lowercase) to server-specific
    settings.
    The special key **default** applies to any server that has no explicit entry.

Supported sub-keys:

**tsig**

:   TSIG credentials used when querying that server.

    **name** *STRING*

    :   TSIG key name.

    **secret** *STRING*

    :   Base64-encoded TSIG secret.

    **algorithm** *STRING*

    :   TSIG algorithm.
        Default: **hmac-sha256**

Example:

```
server_options:
  ns1.example.com:
    tsig:
      name: xymon-key
      algorithm: hmac-sha256
      secret: "base64secret=="
  default:
    tsig:
      name: default-key
      secret: "base64secret=="
```

### **Full configuration example**

```
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
zone_parent_strip_labels: 1
zone_rollover_ds_propagation_delay: 7d:15d

server_options:
  ns1.internal.example.com:
    tsig:
      name: monitor-key
      algorithm: hmac-sha256
      secret: "c2VjcmV0"
```

# HOSTS.CFG OPTIONS

Zones are declared in the Xymon *hosts.cfg* file using the standard host entry syntax.
The probe is activated by adding the **dnssec** service tag to a host line.
The hostname is used as the zone name.

```
1.2.3.4  example.com  # dnssec
```

Per-zone options can be appended after **dnssec=**, as a comma-separated list of
*key*:*value* pairs:

```
1.2.3.4  example.com  # dnssec=permanent_cds_cdnskey:false,strip:2
```

### **Available per-zone options**

**permanent_cds_cdnskey**:*BOOLEAN*

:   Override **zone_require_permanent_cds_cdnskey** for this zone.
    Accepted boolean values: **true**/**false**, **yes**/**no**, **1**/**0**, **on**/**off**.
    Alias: **require_permanent_cds_cdnskey**.

**no_permanent_cds_cdnskey**

:   Shorthand to disable the CDS/CDNSKEY requirement for this zone.
    Equivalent to **permanent_cds_cdnskey:false**.

**strip**:*N*

:   Override **zone_parent_strip_labels** for this zone.
    Alias: **parent_strip_labels**.
    Useful for zones under multi-label public suffixes.

**nsec3**[:*BOOLEAN*]

:   Override **zone_warn_if_no_nsec3** for this zone.
    **nsec3** or **nsec3:true** activates the warning when no NSEC3PARAM record is found.
    **nsec3:false** disables it.
    Accepted boolean values: **true**/**false**, **yes**/**no**, **1**/**0**, **on**/**off**.

**nsec**[:*BOOLEAN*]

:   Declare that this zone intentionally uses NSEC (not NSEC3).
    **nsec** or **nsec:true** suppresses the NSEC3PARAM warning.
    **nsec:false** is equivalent to **nsec3:true**.

**rrsig_delay**:*WARN*:*RED*

:   Override **zone_rrsig_delay** for this zone.
    Uses the same format and partial-value rules as the global setting.
    Examples: **rrsig_delay:3d:12h**, **rrsig_delay:36**, **rrsig_delay::24h**.

**rollover_ds_propagation_delay**:*WARN*:*RED*

:   Override **zone_rollover_ds_propagation_delay** for this zone.
    Uses the same format and partial-value rules as **rrsig_delay**.
    Examples: **rollover_ds_propagation_delay:7d:15d**, **rollover_ds_propagation_delay:10d**.

### **Example hosts.cfg entries**

```
# Standard zone: parent is "org"
1.2.3.4  example.org            # dnssec

# Zone 2 levels below the managed parent: strip 2 to reach "example.com"
1.2.3.4  foo.bar.example.com    # dnssec=strip:2

# Zone that only uses CDS/CDNSKEY during rollovers
1.2.3.4  stable.org             # dnssec=no_permanent_cds_cdnskey

# Zone using NSEC instead of NSEC3
1.2.3.4  legacy.org             # dnssec=nsec

# Zone-specific RRSIG renewal thresholds
1.2.3.4  strict.example          # dnssec=rrsig_delay:3d:12h

# Zone-specific rollover temporal thresholds
1.2.3.4  rollover.example        # dnssec=rollover_ds_propagation_delay:7d:15d
```

# EXIT STATUS

**0**

:   Probe ran successfully (individual zone statuses are sent to Xymon regardless
    of DNSSEC health).

**non-zero**

:   Fatal initialisation error (missing **xymongrep**(1), invalid arguments, etc.).

# ENVIRONMENT

**HOSTSCFG**

:   Path to the Xymon *hosts.cfg* file.
    Set automatically by the Xymon server when the probe is run as a Xymon
    external script.

**XYMONHOME**

:   If set, the probe looks for **xymongrep** under *$XYMONHOME/bin/*.

# FILES

*/etc/xymon/xymon-ext-dnssec.yaml*

:   Default configuration file.

*/etc/xymon/hosts.cfg*

:   Default Xymon hosts configuration file.

# SEE ALSO

**xymon**(1), **xymongrep**(1), **dnssec-publish-ds**(8), **Net::DNS**(3pm)
