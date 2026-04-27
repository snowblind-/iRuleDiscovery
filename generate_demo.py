#!/usr/bin/env python3
"""
Generates a demo irule_viewer.html using synthetic multi-device data.
Simulates one week of 5-minute polling intervals (2,016 data points per iRule)
with realistic business-hours traffic patterns.
No BIG-IP required.  Run: python generate_demo.py
"""

import datetime
import math
import random
from pathlib import Path

from irule_discovery import (
    build_html, irule_key, content_hash, find_duplicate_irules,
    compute_irule_status,
)

random.seed(42)   # reproducible demo

# ── AI analyses (iRule-focused, no migration recommendations) ────────────────

AI_ANALYSES = {
    "irule_xff_insert": """\
## 1. Objective
This iRule ensures every inbound HTTP request carries an accurate
`X-Forwarded-For` header containing the real client IP address, and adds a
companion `X-Real-IP` header for backends that prefer that field.

## 2. Execution Flow
Triggered on `HTTP_REQUEST` for every inbound request.
1. Checks whether an `X-Forwarded-For` header already exists.
2. If it exists, **replaces** it with `[IP::client_addr]` — discarding any
   prior chain supplied by an upstream proxy.
3. If it does not exist, **inserts** a fresh header with the client address.
4. Unconditionally inserts `X-Real-IP` with the same address.

## 3. Recommendations
- **Potential header-chain loss**: replacing an existing `X-Forwarded-For`
  discards legitimate upstream proxy addresses. If BIG-IP sits behind another
  load balancer, consider appending instead:
  `HTTP::header replace "X-Forwarded-For" "[HTTP::header X-Forwarded-For], [IP::client_addr]"`
- **Duplicate X-Real-IP**: if `X-Real-IP` is already present from an upstream
  hop, a second value will be inserted. Add an existence check identical to the
  `X-Forwarded-For` logic.
- **Trusted proxy validation**: consider checking `[IP::client_addr]` against a
  trusted-proxy datagroup before accepting any existing header value, to prevent
  client spoofing.
- **Event choice is correct**: `HTTP_REQUEST` is the right event; no improvement
  needed there.""",

    "irule_ssl_redirect": """\
## 1. Objective
Redirects plain HTTP requests arriving on port 80 to the equivalent HTTPS URL,
enforcing transport security for all clients.

## 2. Execution Flow
Triggered on `HTTP_REQUEST`.
1. Captures `[HTTP::host]` and `[HTTP::uri]` into local variables.
2. Reads `[TCP::local_port]`; if it equals 80, issues an HTTP 302 redirect to
   `https://<host><uri>`.
3. Requests on any other port pass through without modification.

## 3. Recommendations
- **Use 301, not 302**: `HTTP::redirect` defaults to 302 (temporary). For an
  SSL-enforcement redirect use a permanent 301 to allow browser caching:
  `HTTP::respond 301 Location "https://${host}${uri}"`
- **Port check is redundant on a dedicated HTTP VS**: if this iRule is only
  applied to a port-80 virtual server the `[TCP::local_port] == 80` check is
  unnecessary overhead every request. Remove the `if` block.
- **HSTS header**: add `Strict-Transport-Security "max-age=31536000"` to the
  redirect response to prevent future plain-HTTP attempts.
- **Host header validation**: an empty or missing `Host` header would produce a
  malformed redirect URL. Add a guard: `if { $host eq "" } { return }`.""",

    "irule_rate_limit": """\
## 1. Objective
Implements a per-source-IP connection rate limiter using the BIG-IP `table`
subsystem, rejecting clients that exceed 100 connections within a 60-second
sliding window.

## 2. Execution Flow
Triggered on `CLIENT_ACCEPTED` for every new TCP connection.
1. Records the client IP in `$client_ip`.
2. Atomically increments a table entry keyed by client IP using `table incr
   -notouch`, which updates the value without resetting the TTL.
3. On the first connection (`$conn_count == 1`), sets the entry with a 60-second
   lifetime.
4. If the count exceeds 100, logs a warning and calls `reject` to drop the
   connection with a TCP RST.

## 3. Recommendations
- **Race condition on first connection**: `table incr -notouch` followed by
  `table set` on count==1 is not atomic. Two simultaneous first-connections from
  the same IP can both get count==1, causing the TTL never to be set. Use
  `table set -notouch` with an `if { ![table exists $client_ip] }` guard, or
  switch to `table add` which fails silently if the key already exists.
- **`-notouch` prevents TTL reset but also prevents sliding window**: every hit
  after the first does not refresh the timer. A client can make 100 connections
  in second 1, wait 60 seconds, then make another 100. This is a fixed-window,
  not a sliding-window limiter. Document this clearly or implement a true sliding
  window.
- **`reject` vs `drop`**: `reject` sends a TCP RST, which is detectable by
  scanners. Consider `drop` to silently discard the packet instead.
- **Log rate**: `log local0.warn` on every rejected connection can flood the
  syslog under a real attack. Throttle with a separate table entry for the last
  log time per IP.""",

    "irule_jwt_validate": """\
## 1. Objective
Enforces that all inbound HTTP requests carry a Bearer token in the
`Authorization` header, returning a 401 to unauthenticated requests and
forwarding the raw token to the upstream pool as `X-Token-Hint`.

## 2. Execution Flow
Triggered on `HTTP_REQUEST`.
1. Reads the `Authorization` header into `$auth_header`.
2. If the value does not begin with `"Bearer "`, responds immediately with
   HTTP 401, `Content-Type: application/json`, and `WWW-Authenticate` challenge.
3. If valid prefix found, strips the seven-character `"Bearer "` prefix and
   stores the token in `$token`.
4. Inserts `X-Token-Hint: <token>` header and allows the request to proceed.

## 3. Recommendations
- **Token is not validated**: the iRule only checks the prefix, not the token
  value. A request with `Authorization: Bearer invalid` passes through.
  Validate the token with an iRule LX (Node.js) call or `CRYPTO::verify` if
  HS256/RS256 is in use.
- **X-Token-Hint exposes credentials upstream**: forwarding the raw token to
  pool members may be an intentional design, but it should be documented as a
  security decision. If the upstream does not need it, remove the insert.
- **Case sensitivity**: `starts_with "Bearer "` is case-sensitive in TCL.
  RFC 6750 says the scheme is case-insensitive. Normalise with
  `string tolower [string range $auth_header 0 6]` before comparing.
- **Empty Authorization header**: an empty string will fail the `starts_with`
  check correctly, but logging the failure helps with debugging. Add
  `log local0.debug "401 no Bearer from [IP::client_addr]"`.""",

    "irule_maintenance_page": """\
## 1. Objective
Serves a static HTML 503 maintenance page when all pool members are
unavailable, preventing the client from receiving a generic BIG-IP error.

## 2. Execution Flow
Triggered on `HTTP_REQUEST`.
1. Calls `[active_members [LB::server pool]]` to count healthy pool members.
2. If the count is zero, responds immediately with HTTP 503, inline HTML body,
   `Content-Type: text/html`, and `Retry-After: 3600`.
3. If members are available, the request is forwarded normally.

## 3. Recommendations
- **Better event: `HTTP_RESPONSE` or LB::FAILED event**: checking on every
  `HTTP_REQUEST` adds an `active_members` lookup to 100% of traffic. Use the
  `LB_FAILED` event instead — it fires only when load balancing actually fails,
  eliminating the per-request overhead.
- **Inline HTML is fragile**: the HTML is embedded as a TCL string literal. Use
  an iFile for the maintenance page so it can be updated without editing the
  iRule: `ifile get /Common/maintenance.html`.
- **`Retry-After` is hardcoded**: 3600 seconds may not match the actual expected
  downtime. Make this value configurable via a datagroup or iRule variable.
- **No logging**: add `log local0.warn "503 maintenance page served — 0 active
  members in [LB::server pool]"` to create an audit trail.""",

    "irule_geo_block": """\
## 1. Objective
Blocks HTTP requests originating from countries listed in a `blocked_countries`
data group, using BIG-IP's built-in IP geolocation database.

## 2. Execution Flow
Triggered on `HTTP_REQUEST`.
1. Looks up the two-letter country code for `[IP::client_addr]` using the
   `whereis` command.
2. Checks whether the result matches any entry in the `blocked_countries`
   datagroup via `matchclass`.
3. If matched, logs the event and responds with HTTP 403 and plain-text body.
4. If not matched, the request proceeds to the pool.

## 3. Recommendations
- **`whereis` is deprecated**: the `whereis` command is legacy; prefer
  `[IP::country [IP::client_addr]]` which uses the same GeoIP database but is
  the current supported interface and avoids string parsing.
- **Log volume**: `log local0.info` on every blocked request can be noisy for
  heavily targeted regions. Use a rate-limited log or write to an HSL pool
  instead of local syslog.
- **Datagroup lookup is exact-match only**: `matchclass … equals` checks for an
  exact two-letter code. Verify the `blocked_countries` datagroup contains
  ISO 3166-1 alpha-2 codes in the same case that `[IP::country]` returns
  (uppercase). A mismatch silently bypasses the block.
- **No IPv6 handling**: `[IP::client_addr]` returns an IPv6 address for v6
  clients. Confirm that the GeoIP database has IPv6 coverage and that the
  datagroup format handles IPv6-mapped IPv4 addresses correctly.""",
}

# ── iRule TCL source ─────────────────────────────────────────────────────────

IRULES = {
    "irule_xff_insert": """\
# Insert X-Forwarded-For header with the client IP address
when HTTP_REQUEST {
    if { [HTTP::header exists "X-Forwarded-For"] } {
        HTTP::header replace "X-Forwarded-For" [IP::client_addr]
    } else {
        HTTP::header insert "X-Forwarded-For" [IP::client_addr]
    }
    HTTP::header insert "X-Real-IP" [IP::client_addr]
}""",

    "irule_ssl_redirect": """\
# Redirect plain HTTP traffic to HTTPS
when HTTP_REQUEST {
    set host [HTTP::host]
    set uri  [HTTP::uri]
    if { [TCP::local_port] == 80 } {
        HTTP::redirect "https://${host}${uri}"
    }
}""",

    "irule_rate_limit": """\
# Simple connection rate limiter using the table command
when CLIENT_ACCEPTED {
    set client_ip [IP::client_addr]
    set conn_count [table incr -notouch $client_ip]
    if { $conn_count == 1 } {
        table set $client_ip 1 60
    }
    if { $conn_count > 100 } {
        log local0.warn "Rate limit exceeded for $client_ip (count=$conn_count)"
        reject
    }
}""",

    "irule_jwt_validate": """\
# Validate Bearer token presence and forward to pool
when HTTP_REQUEST {
    set auth_header [HTTP::header "Authorization"]
    if { not ($auth_header starts_with "Bearer ") } {
        HTTP::respond 401 content "Unauthorized" \\
            "Content-Type" "application/json" \\
            "WWW-Authenticate" "Bearer realm=\\"api\\""
        return
    }
    set token [string range $auth_header 7 end]
    HTTP::header insert "X-Token-Hint" $token
}""",

    "irule_maintenance_page": """\
# Return a maintenance page when the pool has no active members
when HTTP_REQUEST {
    if { [active_members [LB::server pool]] == 0 } {
        HTTP::respond 503 content {
<html><body><h1>Service Unavailable</h1>
<p>Scheduled maintenance in progress.</p>
</body></html>
        } "Content-Type" "text/html" "Retry-After" "3600"
    }
}""",

    "irule_geo_block": """\
# Block requests from specific countries using IP geolocation class
when HTTP_REQUEST {
    set country [whereis [IP::client_addr] country]
    if { [matchclass $country equals blocked_countries] } {
        log local0.info "Geo-blocked: [IP::client_addr] ($country)"
        HTTP::respond 403 content "Access Denied" "Content-Type" "text/plain"
    }
}""",
}

# ── Traffic profiles ─────────────────────────────────────────────────────────
# base_rate   : average executions per 5-min interval at peak business hours
# error_rate  : fraction of intervals that have failures or aborts (0–1)
# weekend_frac: traffic level on weekends relative to weekday peak
# night_frac  : traffic level overnight (midnight–6am) relative to peak

TRAFFIC = {
    #                     base  err_rate  weekend  night
    "irule_xff_insert":   (85,   0.00,    0.20,    0.04),
    "irule_ssl_redirect": (50,   0.00,    0.25,    0.05),
    "irule_rate_limit":   (130,  0.00,    0.18,    0.03),
    "irule_jwt_validate": (40,   0.04,    0.15,    0.08),   # API — some bad tokens
    "irule_maintenance_page": (3, 0.00,   0.30,    0.10),   # rarely triggered
    "irule_geo_block":    (28,   0.02,    0.20,    0.05),   # occasional failures
}


def _time_factor(ts: datetime.datetime, weekend_frac: float,
                 night_frac: float) -> float:
    """Return a multiplier (0–1) based on time of day and day of week."""
    dow  = ts.weekday()   # 0=Monday
    hour = ts.hour + ts.minute / 60.0

    if dow >= 5:          # weekend
        base = weekend_frac
    elif 9 <= hour < 17:  # business hours
        base = 1.0
    elif 7 <= hour < 9 or 17 <= hour < 20:
        base = 0.40
    else:
        base = night_frac

    # Smooth with a cosine so there are no hard edges
    phase = math.cos(math.pi * hour / 12) * 0.08
    return max(0.01, base + phase)


def generate_stats_history(short_name: str) -> list[dict]:
    """
    Produce 2,016 five-minute snapshots spanning exactly one week.
    Returns history with both cumulative total_executions and
    delta_executions (executions since previous poll).
    """
    base, err_rate, wknd, night = TRAFFIC[short_name]

    now   = datetime.datetime.now(datetime.timezone.utc).replace(second=0, microsecond=0, tzinfo=None)
    # Align to next 5-min boundary
    now  -= datetime.timedelta(minutes=now.minute % 5)
    start = now - datetime.timedelta(weeks=1)

    INTERVAL   = datetime.timedelta(minutes=5)
    N          = 7 * 24 * 12   # 2,016 points

    history    = []
    cumulative = random.randint(5_000, 200_000)   # plausible starting counter

    for i in range(N):
        ts     = start + INTERVAL * i
        factor = _time_factor(ts, wknd, night)

        # Gaussian noise around the time-scaled base rate
        delta  = max(0, int(base * factor * random.gauss(1.0, 0.28)))

        # Sporadic failures / aborts
        failures = aborts = 0
        if err_rate > 0 and random.random() < err_rate:
            failures = random.randint(1, max(1, delta // 20 + 1))
        if err_rate > 0 and random.random() < err_rate * 0.4:
            aborts   = random.randint(1, max(1, delta // 30 + 1))

        cumulative += delta
        history.append({
            "run_at":            ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_executions":  cumulative,
            "delta_executions":  delta,
            "failures":          failures,
            "aborts":            aborts,
        })

    return history


# ── Two synthetic BIG-IP devices ─────────────────────────────────────────────

DEVICES = [
    {
        "host": "bigip-dc1.example.com",
        "virtual_servers": [
            {
                "name":       "vs_web_443",
                "full_path":  "/Common/vs_web_443",
                "partition":  "Common",
                "rules":      ["irule_xff_insert", "irule_ssl_redirect", "irule_rate_limit"],
            },
            {
                "name":       "vs_api_8443",
                "full_path":  "/Common/vs_api_8443",
                "partition":  "Common",
                "rules":      ["irule_jwt_validate", "irule_rate_limit"],
            },
            {
                "name":       "vs_legacy_80",
                "full_path":  "/Common/vs_legacy_80",
                "partition":  "Common",
                "rules":      ["irule_ssl_redirect", "irule_maintenance_page"],
            },
        ],
    },
    {
        "host": "bigip-dc2.example.com",
        "virtual_servers": [
            {
                "name":       "vs_public_443",
                "full_path":  "/Common/vs_public_443",
                "partition":  "Common",
                "rules":      ["irule_geo_block", "irule_xff_insert", "irule_rate_limit"],
            },
            {
                "name":       "vs_internal_api",
                "full_path":  "/Prod/vs_internal_api",
                "partition":  "Prod",
                "rules":      ["irule_jwt_validate"],
            },
        ],
    },
]

# ── Build manifest ────────────────────────────────────────────────────────────

print("Generating one week of 5-minute polling data …")

irules_data: dict = {}
device_records: list = []

for dev in DEVICES:
    vs_list = []
    for vs in dev["virtual_servers"]:
        rule_keys = []
        for short_name in vs["rules"]:
            rule_path = f"/Common/{short_name}"
            key = irule_key(dev["host"], rule_path)
            if key not in irules_data:
                analysis_text = AI_ANALYSES.get(short_name)
                code          = IRULES.get(short_name, "# source not available")
                history       = generate_stats_history(short_name)
                latest        = history[-1]
                stats = {
                    "total_executions": latest["total_executions"],
                    "failures":         sum(h["failures"] for h in history),
                    "aborts":           sum(h["aborts"]   for h in history),
                    "events":           {},
                }
                irules_data[key] = {
                    "host":            dev["host"],
                    "path":            rule_path,
                    "file":            f"irule_output/irules/"
                                       f"{dev['host'].replace('.','_')}__{short_name}.tcl",
                    "code":            code,
                    "content_hash":    content_hash(code),
                    "duplicate_keys":  [],
                    "orphan":          False,
                    "stats":           stats,
                    "stats_history":   history,
                    "xc_library":      None,
                    "ai_analysis": {
                        "status":   "success" if analysis_text else "failed",
                        "analysis": analysis_text or "Analysis not available.",
                        "provider": "anthropic",
                        "model":    "claude-sonnet-4-6",
                    },
                    "ai_analysis_file": (
                        f"irule_output/irules/"
                        f"{dev['host'].replace('.','_')}__{short_name}.analysis.txt"
                        if analysis_text else None
                    ),
                }
            rule_keys.append(key)
        vs_list.append({
            "name":       vs["name"],
            "full_path":  vs["full_path"],
            "partition":  vs["partition"],
            "rule_keys":  rule_keys,
        })
    device_records.append({"host": dev["host"], "error": None,
                            "virtual_servers": vs_list})

find_duplicate_irules(irules_data)

# Compute status after duplicates are resolved
for entry in irules_data.values():
    entry["irule_status"] = compute_irule_status(entry)

manifest = {"devices": device_records, "irules": irules_data}

out    = Path("irule_output")
out.mkdir(exist_ok=True)
viewer = out / "irule_viewer.html"
viewer.write_text(build_html(manifest), encoding="utf-8")

total_pts = sum(len(e["stats_history"]) for e in irules_data.values())
print(f"  {len(irules_data)} iRules · {total_pts:,} stat data points")
print(f"Demo viewer → {viewer.resolve()}")
print(f"Open with:    open '{viewer.resolve()}'")
