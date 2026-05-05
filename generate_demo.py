#!/usr/bin/env python3
"""
Generates a demo irule_viewer.html using 10 synthetic BIG-IP devices.
Simulates one week of 5-minute polling intervals (2,016 data points per iRule)
with realistic business-hours traffic patterns and per-device scaling.
No BIG-IP required.  Run: python3 generate_demo.py
"""

import datetime
import math
import random
from pathlib import Path

from irule_discovery import (
    build_html, content_hash, find_duplicate_irules, compute_irule_status,
    open_db, init_db,
)

# ── AI analyses ───────────────────────────────────────────────────────────────

AI_ANALYSES = {

"irule_xff_insert": """\
## 1. Objective
Ensures every inbound HTTP request carries an accurate `X-Forwarded-For` header
with the real client IP, and adds a companion `X-Real-IP` header for backends
that prefer that field.

## 2. Execution Flow
Triggered on `HTTP_REQUEST` for every inbound request.
1. Checks whether `X-Forwarded-For` already exists.
2. Replaces it with `[IP::client_addr]` if present, otherwise inserts it fresh.
3. Unconditionally inserts `X-Real-IP` with the same address.

## 3. Recommendations
- **Header-chain loss**: replacing an existing XFF discards upstream proxy hops.
  If BIG-IP sits behind another LB, append instead:
  `HTTP::header replace "X-Forwarded-For" "[HTTP::header X-Forwarded-For], [IP::client_addr]"`
- **Duplicate X-Real-IP**: add an existence check to avoid inserting twice.
- **Trusted proxy validation**: check `[IP::client_addr]` against a trusted-proxy
  datagroup before accepting any existing header value.""",

"irule_ssl_redirect": """\
## 1. Objective
Redirects plain HTTP requests arriving on port 80 to the equivalent HTTPS URL,
enforcing transport security for all clients.

## 2. Execution Flow
Triggered on `HTTP_REQUEST`.
1. Captures `[HTTP::host]` and `[HTTP::uri]`.
2. If `[TCP::local_port]` equals 80, issues an HTTP 302 redirect to `https://`.
3. Requests on other ports pass through unmodified.

## 3. Recommendations
- **Use 301 not 302**: a permanent redirect allows browser caching and avoids
  round-trips on repeat visits.
- **Port check is redundant on a port-80-only VS**: remove the `if` block.
- **Add HSTS**: include `Strict-Transport-Security "max-age=31536000"` in the
  redirect response to prevent future plain-HTTP attempts.
- **Guard empty Host**: an empty or missing `Host` produces a malformed redirect URL.""",

"irule_rate_limit": """\
## 1. Objective
Implements a per-source-IP connection rate limiter using the BIG-IP `table`
subsystem, rejecting clients that exceed 100 connections within 60 seconds.

## 2. Execution Flow
Triggered on `CLIENT_ACCEPTED`.
1. Atomically increments a table entry keyed by client IP with `table incr -notouch`.
2. On the first connection sets a 60-second lifetime for the entry.
3. Rejects with TCP RST and logs when the count exceeds 100.

## 3. Recommendations
- **Race condition on first connection**: use `table add` (fails silently if the
  key exists) instead of the incr-then-set pattern.
- **Fixed window, not sliding window**: document this or implement a true sliding
  window if the use-case demands it.
- **Use `drop` over `reject`**: `reject` sends a TCP RST that is detectable by
  scanners; `drop` silently discards.
- **Log rate**: throttle syslog under attack with a rate-limit table entry.""",

"irule_jwt_validate": """\
## 1. Objective
Enforces that all inbound HTTP requests carry a Bearer token in the
`Authorization` header, returning 401 to unauthenticated requests and
forwarding the raw token upstream as `X-Token-Hint`.

## 2. Execution Flow
Triggered on `HTTP_REQUEST`.
1. Reads the `Authorization` header.
2. If the value doesn't begin with `"Bearer "`, responds with HTTP 401.
3. Otherwise strips the prefix, stores the token, and inserts `X-Token-Hint`.

## 3. Recommendations
- **Token is not validated**: only the prefix is checked. Use iRule LX or
  `CRYPTO::verify` to validate the token signature.
- **X-Token-Hint exposes credentials upstream**: document this as a deliberate
  security decision or remove it.
- **Case sensitivity**: RFC 6750 says the scheme is case-insensitive. Normalise
  with `string tolower` before comparing.
- **Log rejections**: `log local0.debug "401 no Bearer from [IP::client_addr]"`.""",

"irule_maintenance_page": """\
## 1. Objective
Serves a static HTML 503 maintenance page when all pool members are unavailable,
preventing the client from receiving a generic BIG-IP error page.

## 2. Execution Flow
Triggered on `HTTP_REQUEST`.
1. Calls `[active_members]` to count healthy pool members.
2. If zero, responds immediately with HTTP 503, inline HTML, and `Retry-After: 3600`.
3. If members are available, the request is forwarded normally.

## 3. Recommendations
- **Use `LB_FAILED` event**: checking on every request adds an `active_members`
  lookup to 100% of traffic. `LB_FAILED` fires only when LB actually fails.
- **Inline HTML is fragile**: use `ifile get /Common/maintenance.html` so the
  page can be updated without editing the iRule.
- **Hardcoded Retry-After**: make this configurable via a datagroup.
- **Add logging**: create an audit trail with `log local0.warn`.""",

"irule_geo_block": """\
## 1. Objective
Blocks HTTP requests from countries listed in a `blocked_countries` datagroup
using BIG-IP's built-in IP geolocation database.

## 2. Execution Flow
Triggered on `HTTP_REQUEST`.
1. Looks up the two-letter country code with `whereis`.
2. Checks against the `blocked_countries` datagroup via `matchclass`.
3. Returns HTTP 403 and logs if matched; otherwise forwards normally.

## 3. Recommendations
- **`whereis` is deprecated**: prefer `[IP::country [IP::client_addr]]` — the
  current supported interface.
- **Log volume**: use HSL or rate-limited logging for heavily targeted regions.
- **Case sensitivity**: verify the datagroup contains uppercase ISO 3166-1 codes
  to match what `[IP::country]` returns.
- **No IPv6 handling**: confirm GeoIP database coverage for IPv6 clients.""",

"irule_header_sanitize": """\
## 1. Objective
Strips sensitive internal headers that clients could inject to bypass security
controls, and truncates oversized User-Agent strings to prevent buffer-related
issues in upstream applications.

## 2. Execution Flow
Triggered on `HTTP_REQUEST`.
1. Iterates a hardcoded list of four sensitive header names.
2. Removes each header if present using `HTTP::header remove`.
3. Reads the User-Agent header and truncates it to 512 characters if longer.

## 3. Recommendations
- **Use a datagroup for the header list**: move sensitive header names to a
  string-type datagroup so operators can update them without a code change.
- **`foreach` overhead**: iterate `HTTP::header names` and filter once rather
  than calling `HTTP::header exists` per hard-coded name.
- **Truncation vs removal**: for security-sensitive headers, removal is safer
  than truncation. Document the rationale for the 512-byte threshold.
- **Missing response sanitisation**: add `HTTP_RESPONSE` to strip any internal
  headers that pool members emit on the way back.""",

"irule_uri_rewrite": """\
## 1. Objective
Rewrites legacy `/api/v1/` paths to their v2 equivalents for transparent backend
migration and normalises URLs by removing trailing slashes via redirect.

## 2. Execution Flow
Triggered on `HTTP_REQUEST`.
1. Reads the current URI into `$uri`.
2. If the URI starts with `/api/v1/`, rewrites to `/api/v2/` and inserts
   `X-Rewritten-From` for audit visibility.
3. If the URI ends with `/` (but is not the root), issues a 302 redirect
   removing the trailing slash.

## 3. Recommendations
- **Trailing-slash redirect after v1 rewrite**: a `/api/v1/foo/` request matches
  both branches — the rewrite runs first, then the redirect fires on the rewritten
  URI. Add `return` after the v2 rewrite to prevent double-processing.
- **Redirect scheme**: `[HTTP::host]` may omit the port. Reconstruct the full URL
  from `[HTTP::host]:[TCP::local_port]` or use `[HTTP::header "Host"]`.
- **`X-Rewritten-From` from untrusted clients**: remove or replace this header if
  it is already present from the client before inserting your own value.""",

"irule_bot_detect": """\
## 1. Objective
Blocks requests whose User-Agent matches a list of known scanning and attack tools,
and rejects requests with an empty User-Agent which is common bot behaviour.

## 2. Execution Flow
Triggered on `HTTP_REQUEST`.
1. Lower-cases the User-Agent into `$ua`.
2. Iterates a hardcoded list of 7 bot signatures using `foreach` / `contains`.
3. Returns HTTP 403 with a `log local0.warn` on any match.
4. Returns HTTP 400 on empty User-Agent.

## 3. Recommendations
- **Use a datagroup**: move bot signatures to a string-type datagroup and use
  `matchclass` — faster and operator-updatable without a code change.
- **`contains` matches substrings**: `"masscan"` would match `"notmasscan"`.
  Use exact-match datagroup entries or anchor the match more precisely.
- **Empty User-Agent is aggressive**: health-check and monitoring agents often
  omit User-Agent. Allowlist trusted source IPs before this check.
- **Log rate risk**: throttle `log local0.warn` per source IP using the table
  command to avoid syslog flooding during a scan.""",

"irule_log_hsl": """\
## 1. Objective
Implements high-speed request/response logging via a UDP HSL channel, emitting
a structured syslog-format record containing client IP, HTTP method, URI, status
code, and request latency for each transaction.

## 2. Execution Flow
`HTTP_REQUEST`: opens HSL channel, generates request ID, records start timestamp,
inserts `X-Request-ID` header.
`HTTP_RESPONSE`: computes latency from stored timestamp, emits the log record via
`HSL::send`.

## 3. Recommendations
- **HSL::open on every request is expensive**: open the channel once with a
  static variable — `if { ![info exists hsl] } { set hsl [HSL::open …] }`.
- **`rand()` for request ID collides**: combine `[clock microseconds]` with
  `[IP::client_addr]` for a low-collision ID.
- **Variables across events**: `$req_time` and `$request_id` rely on session
  persistence between events — test under HTTP/2 multiplexing.
- **Log format with spaces in URI**: URL-encode or quote field values to prevent
  unparseable log records if the URI contains spaces.""",
}

# ── ServiceNow reference data ─────────────────────────────────────────────────
# Keyed by short iRule name. Each list entry becomes a row in servicenow_refs.
# Ticket numbers match the comments already embedded in the iRule source above.

SERVICENOW_REFS = {

"irule_xff_insert": [
    {
        "ticket_number":   "CHG0042891",
        "ticket_type":     "CHG",
        "context_snippet": "# CHG0042891 — required for upstream application to see real client IP",
        "llm_summary":     "Change request to insert X-Forwarded-For and X-Real-IP headers so "
                           "upstream application servers can identify the originating client IP "
                           "address behind the BIG-IP load balancer.",
    },
],

"irule_ssl_redirect": [
    {
        "ticket_number":   "INC0018374",
        "ticket_type":     "INC",
        "context_snippet": "# INC0018374 — added to enforce TLS across all public virtual servers",
        "llm_summary":     "Incident raised after security audit found plain HTTP traffic reaching "
                           "backend servers without TLS enforcement. iRule added to redirect all "
                           "port-80 requests to HTTPS.",
    },
],

"irule_rate_limit": [
    {
        "ticket_number":   "RITM0098312",
        "ticket_type":     "RITM",
        "context_snippet": "# RITM0098312 — rate limiting per client IP, 100 req/s burst, 60s window",
        "llm_summary":     "Requested item to implement connection-rate limiting using the BIG-IP "
                           "table command. Configured for 100 connections per 60-second window per "
                           "source IP to mitigate abuse and CVE-2023-44487 HTTP/2 Rapid Reset vectors.",
    },
],

"irule_jwt_validate": [
    {
        "ticket_number":   "CHG0051209",
        "ticket_type":     "CHG",
        "context_snippet": "# CHG0051209 — added JWT gate for API endpoints",
        "llm_summary":     "Change to enforce Bearer token presence on all API virtual server "
                           "requests before forwarding to the pool. Unauthenticated requests "
                           "receive HTTP 401.",
    },
    {
        "ticket_number":   "PRB0007412",
        "ticket_type":     "PRB",
        "context_snippet": "# see PRB0007412 for token leak fix",
        "llm_summary":     "Problem record documenting discovery that the X-Token-Hint header was "
                           "being logged by upstream application servers, exposing raw Bearer tokens "
                           "in application logs. Remediation pending review of header forwarding policy.",
    },
],

"irule_geo_block": [
    {
        "ticket_number":   "CHG0038100",
        "ticket_type":     "CHG",
        "context_snippet": "# CHG0038100 — geo-blocking added per compliance requirement REQ0002847",
        "llm_summary":     "Change implementing geolocation-based blocking using the BIG-IP IP "
                           "intelligence database. Blocks requests from countries listed in the "
                           "blocked_countries datagroup, driven by compliance requirement REQ0002847.",
    },
],

"irule_header_sanitize": [
    {
        "ticket_number":   "INC0021009",
        "ticket_type":     "INC",
        "context_snippet": "# INC0021009 — SSRF via X-Internal-Token injection, pattern matches CVE-2021-26855",
        "llm_summary":     "Incident reporting a successful SSRF attack via injected X-Internal-Token "
                           "header that bypassed application-layer authentication. iRule added to strip "
                           "sensitive internal headers at the BIG-IP layer. Matches CVE-2021-26855 "
                           "attack pattern.",
    },
],

"irule_uri_rewrite": [
    {
        "ticket_number":   "RITM0110045",
        "ticket_type":     "RITM",
        "context_snippet": "# RITM0110045 — v1-to-v2 migration shim, retire after Q3 cutover",
        "llm_summary":     "Requested item to implement a transparent API version migration shim. "
                           "Rewrites /api/v1/ paths to /api/v2/ to allow backend migration without "
                           "client changes. Marked for retirement after Q3 cutover is complete.",
    },
],

"irule_bot_detect": [
    {
        "ticket_number":   "CHG0059933",
        "ticket_type":     "CHG",
        "context_snippet": "# CHG0059933 — added after bot-driven load spike, INC0031877",
        "llm_summary":     "Emergency change to implement User-Agent-based bot detection after a "
                           "scanning bot caused a significant load spike on production. Blocks "
                           "known scanner signatures including masscan, zgrab, nikto, and sqlmap.",
    },
    {
        "ticket_number":   "INC0031877",
        "ticket_type":     "INC",
        "context_snippet": "# INC0031877 — bot-driven load spike triggered this change",
        "llm_summary":     "Incident report for production load spike caused by automated scanning "
                           "bots. Zgrab and Masscan traffic accounted for 34% of request volume "
                           "over a 6-hour window. Root cause of CHG0059933.",
    },
],

"irule_log_hsl": [
    {
        "ticket_number":   "RITM0088271",
        "ticket_type":     "RITM",
        "context_snippet": "# RITM0088271 — centralised request logging for SIEM ingestion",
        "llm_summary":     "Requested item to implement high-speed UDP syslog forwarding of HTTP "
                           "request metadata to the SIEM platform. Captures client IP, method, URI, "
                           "HTTP status code, and request latency for every transaction.",
    },
],
}

# ── iRule TCL source ──────────────────────────────────────────────────────────

IRULES = {

"irule_xff_insert": """\
# Insert X-Forwarded-For and X-Real-IP headers with the client IP address
# CHG0042891 — required for upstream application to see real client IP
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
# INC0018374 — added to enforce TLS across all public virtual servers
when HTTP_REQUEST {
    set host [HTTP::host]
    set uri  [HTTP::uri]
    if { [TCP::local_port] == 80 } {
        HTTP::redirect "https://${host}${uri}"
    }
}""",

"irule_rate_limit": """\
# Simple connection rate limiter using the table command
# RITM0098312 — rate limiting per client IP, 100 req/s burst, 60s window
# Rate limiting also mitigates CVE-2023-44487 HTTP/2 Rapid Reset attack vectors
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
# CHG0051209 — added JWT gate for API endpoints, see PRB0007412 for token leak fix
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
# CHG0038100 — geo-blocking added per compliance requirement REQ0002847
when HTTP_REQUEST {
    set country [whereis [IP::client_addr] country]
    if { [matchclass $country equals blocked_countries] } {
        log local0.info "Geo-blocked: [IP::client_addr] ($country)"
        HTTP::respond 403 content "Access Denied" "Content-Type" "text/plain"
    }
}""",

"irule_header_sanitize": """\
# Strip sensitive internal headers and sanitize User-Agent length
# INC0021009 — SSRF via X-Internal-Token injection, pattern matches CVE-2021-26855
when HTTP_REQUEST {
    foreach header { "X-Internal-Token" "X-Admin-Key" "X-Debug-Mode" "X-Original-IP" } {
        if { [HTTP::header exists $header] } {
            HTTP::header remove $header
        }
    }
    set ua [HTTP::header "User-Agent"]
    if { [string length $ua] > 512 } {
        HTTP::header replace "User-Agent" [string range $ua 0 511]
    }
}""",

"irule_uri_rewrite": """\
# Rewrite legacy API v1 paths to v2 and normalise trailing slashes
# RITM0110045 — v1-to-v2 migration shim, retire after Q3 cutover
when HTTP_REQUEST {
    set uri [HTTP::uri]
    if { $uri starts_with "/api/v1/" } {
        set new_uri "/api/v2/[string range $uri 8 end]"
        HTTP::uri $new_uri
        HTTP::header insert "X-Rewritten-From" $uri
    }
    if { $uri ends_with "/" && $uri ne "/" } {
        HTTP::redirect "[HTTP::host][string range $uri 0 end-1]"
    }
}""",

"irule_bot_detect": """\
# Detect and block known scanner and bot User-Agent strings
# CHG0059933 — added after bot-driven load spike, INC0031877
# Mitigates CVE-2023-44487 (HTTP/2 Rapid Reset DDoS) and CVE-2021-41773 scanner activity
when HTTP_REQUEST {
    set ua [string tolower [HTTP::header "User-Agent"]]
    set bad_bots [list "masscan" "zgrab" "nikto" "sqlmap" "nmap" "nuclei" "dirbuster"]
    foreach bot $bad_bots {
        if { $ua contains $bot } {
            log local0.warn "Bot blocked: $bot from [IP::client_addr]"
            HTTP::respond 403 content "Forbidden" "Content-Type" "text/plain"
            return
        }
    }
    if { $ua eq "" } {
        HTTP::respond 400 content "Bad Request" "Content-Type" "text/plain"
        return
    }
}""",

"irule_log_hsl": """\
# High-speed logging of HTTP requests and response codes via UDP HSL
# RITM0088271 — centralised request logging for SIEM ingestion
when HTTP_REQUEST {
    set hsl [HSL::open -proto UDP /Common/hsl-pool]
    set request_id [expr { int(rand() * 1000000) }]
    set req_time [clock milliseconds]
    set client_ip [IP::client_addr]
    set method [HTTP::method]
    set uri [HTTP::uri]
    HTTP::header insert "X-Request-ID" $request_id
}
when HTTP_RESPONSE {
    set resp_time [expr { [clock milliseconds] - $req_time }]
    HSL::send $hsl "<190>[F5] client=$client_ip method=$method uri=$uri status=[HTTP::status] latency=${resp_time}ms reqid=$request_id"
}""",
}

# ── Traffic profiles ──────────────────────────────────────────────────────────
# (base_rate, error_rate, weekend_frac, night_frac)

TRAFFIC = {
    "irule_xff_insert":       ( 85,  0.00, 0.20, 0.04),
    "irule_ssl_redirect":     ( 50,  0.00, 0.25, 0.05),
    "irule_rate_limit":       (130,  0.00, 0.18, 0.03),
    "irule_jwt_validate":     ( 40,  0.04, 0.15, 0.08),
    "irule_maintenance_page": (  3,  0.00, 0.30, 0.10),
    "irule_geo_block":        ( 28,  0.02, 0.20, 0.05),
    "irule_header_sanitize":  ( 72,  0.00, 0.22, 0.04),
    "irule_uri_rewrite":      ( 55,  0.01, 0.18, 0.06),
    "irule_bot_detect":       ( 18,  0.08, 0.25, 0.15),  # high error rate — lots of bots
    "irule_log_hsl":          (110,  0.01, 0.20, 0.05),
}


def _time_factor(ts: datetime.datetime, weekend_frac: float,
                 night_frac: float) -> float:
    dow  = ts.weekday()
    hour = ts.hour + ts.minute / 60.0
    if dow >= 5:
        base = weekend_frac
    elif 9 <= hour < 17:
        base = 1.0
    elif 7 <= hour < 9 or 17 <= hour < 20:
        base = 0.40
    else:
        base = night_frac
    phase = math.cos(math.pi * hour / 12) * 0.08
    return max(0.01, base + phase)


def generate_stats_history(short_name: str, scale: float = 1.0,
                            seed: int = 42) -> list[dict]:
    """
    Produce 2,016 five-minute snapshots spanning one week.
    scale adjusts the base traffic level (e.g. 0.03 for DR standby).
    seed ensures each device+iRule combination is independently reproducible.
    """
    random.seed(seed)
    base, err_rate, wknd, night = TRAFFIC[short_name]
    base = max(1, int(base * scale))

    now   = datetime.datetime.now(datetime.timezone.utc).replace(
                second=0, microsecond=0, tzinfo=None)
    now  -= datetime.timedelta(minutes=now.minute % 5)
    start = now - datetime.timedelta(weeks=1)

    INTERVAL   = datetime.timedelta(minutes=5)
    N          = 7 * 24 * 12  # 2,016 points
    history    = []
    cumulative = random.randint(5_000, 200_000)

    for i in range(N):
        ts     = start + INTERVAL * i
        factor = _time_factor(ts, wknd, night)
        delta  = max(0, int(base * factor * random.gauss(1.0, 0.28)))

        failures = aborts = 0
        if err_rate > 0 and random.random() < err_rate:
            failures = random.randint(1, max(1, delta // 20 + 1))
        if err_rate > 0 and random.random() < err_rate * 0.4:
            aborts   = random.randint(1, max(1, delta // 30 + 1))

        cumulative += delta
        history.append({
            "run_at":           ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "total_executions": cumulative,
            "delta_executions": delta,
            "failures":         failures,
            "aborts":           aborts,
        })

    return history


# ── 10 synthetic BIG-IP devices ───────────────────────────────────────────────
#
# scale  : traffic multiplier (1.0 = prod, 0.03 = DR standby, 0 = unreachable)
# error  : set to a string to mark the device as unreachable

DEVICES = [
    # ── Production data-centre 1 ─────────────────────────────────────────────
    {
        "host":  "bigip-prod-dc1.example.com",
        "scale": 1.0,
        "virtual_servers": [
            {"name": "vs_web_443",    "full_path": "/Common/vs_web_443",
             "rules": ["irule_xff_insert", "irule_ssl_redirect", "irule_rate_limit"]},
            {"name": "vs_api_8443",   "full_path": "/Common/vs_api_8443",
             "rules": ["irule_jwt_validate", "irule_rate_limit", "irule_log_hsl"]},
            {"name": "vs_legacy_80",  "full_path": "/Common/vs_legacy_80",
             "rules": ["irule_ssl_redirect", "irule_maintenance_page"]},
            {"name": "vs_internal",   "full_path": "/Prod/vs_internal",
             "rules": ["irule_header_sanitize", "irule_log_hsl"]},
        ],
    },
    # ── Production data-centre 2 ─────────────────────────────────────────────
    {
        "host":  "bigip-prod-dc2.example.com",
        "scale": 1.0,
        "virtual_servers": [
            {"name": "vs_public_443",   "full_path": "/Common/vs_public_443",
             "rules": ["irule_geo_block", "irule_xff_insert", "irule_rate_limit"]},
            {"name": "vs_internal_api", "full_path": "/Prod/vs_internal_api",
             "rules": ["irule_jwt_validate", "irule_log_hsl"]},
            {"name": "vs_web_80",       "full_path": "/Common/vs_web_80",
             "rules": ["irule_ssl_redirect", "irule_xff_insert"]},
        ],
    },
    # ── Disaster recovery site 1 (standby — minimal traffic) ─────────────────
    {
        "host":  "bigip-dr1.example.com",
        "scale": 0.03,
        "virtual_servers": [
            {"name": "vs_web_443",  "full_path": "/Common/vs_web_443",
             "rules": ["irule_xff_insert", "irule_ssl_redirect", "irule_rate_limit"]},
            {"name": "vs_api_8443", "full_path": "/Common/vs_api_8443",
             "rules": ["irule_jwt_validate"]},
        ],
    },
    # ── Disaster recovery site 2 (standby) ────────────────────────────────────
    {
        "host":  "bigip-dr2.example.com",
        "scale": 0.03,
        "virtual_servers": [
            {"name": "vs_web_443",    "full_path": "/Common/vs_web_443",
             "rules": ["irule_xff_insert", "irule_ssl_redirect"]},
            {"name": "vs_public_443", "full_path": "/Common/vs_public_443",
             "rules": ["irule_geo_block", "irule_xff_insert"]},
        ],
    },
    # ── DMZ / perimeter (external-facing, higher bot/error rate) ─────────────
    {
        "host":  "bigip-dmz.example.com",
        "scale": 0.7,
        "virtual_servers": [
            {"name": "vs_external_443", "full_path": "/DMZ/vs_external_443",
             "rules": ["irule_geo_block", "irule_bot_detect", "irule_rate_limit"]},
            {"name": "vs_api_public",   "full_path": "/DMZ/vs_api_public",
             "rules": ["irule_jwt_validate", "irule_bot_detect", "irule_xff_insert"]},
        ],
    },
    # ── Corporate VPN / remote-access ────────────────────────────────────────
    {
        "host":  "bigip-vpn.example.com",
        "scale": 0.45,
        "virtual_servers": [
            {"name": "vs_vpn_443",    "full_path": "/Common/vs_vpn_443",
             "rules": ["irule_xff_insert", "irule_header_sanitize"]},
            {"name": "vs_remote_api", "full_path": "/Common/vs_remote_api",
             "rules": ["irule_jwt_validate", "irule_log_hsl", "irule_rate_limit"]},
        ],
    },
    # ── Development environment ───────────────────────────────────────────────
    {
        "host":  "bigip-dev.example.com",
        "scale": 0.18,
        "virtual_servers": [
            {"name": "vs_dev_web", "full_path": "/Dev/vs_dev_web",
             "rules": ["irule_xff_insert", "irule_uri_rewrite", "irule_maintenance_page"]},
            {"name": "vs_dev_api", "full_path": "/Dev/vs_dev_api",
             "rules": ["irule_jwt_validate", "irule_rate_limit"]},
        ],
    },
    # ── Staging environment ────────────────────────────────────────────────────
    {
        "host":  "bigip-staging.example.com",
        "scale": 0.30,
        "virtual_servers": [
            {"name": "vs_stg_web", "full_path": "/Staging/vs_stg_web",
             "rules": ["irule_xff_insert", "irule_ssl_redirect", "irule_rate_limit"]},
            {"name": "vs_stg_api", "full_path": "/Staging/vs_stg_api",
             "rules": ["irule_header_sanitize", "irule_jwt_validate", "irule_log_hsl"]},
            {"name": "vs_stg_uri", "full_path": "/Staging/vs_stg_uri",
             "rules": ["irule_uri_rewrite"]},
        ],
    },
    # ── CDN edge (high traffic) ───────────────────────────────────────────────
    {
        "host":  "bigip-cdn-edge.example.com",
        "scale": 2.6,
        "virtual_servers": [
            {"name": "vs_cdn_443",  "full_path": "/CDN/vs_cdn_443",
             "rules": ["irule_xff_insert", "irule_geo_block", "irule_bot_detect",
                       "irule_rate_limit"]},
            {"name": "vs_cdn_api",  "full_path": "/CDN/vs_cdn_api",
             "rules": ["irule_bot_detect", "irule_rate_limit", "irule_log_hsl"]},
            {"name": "vs_cdn_rewrite", "full_path": "/CDN/vs_cdn_rewrite",
             "rules": ["irule_uri_rewrite", "irule_xff_insert"]},
        ],
    },
    # ── Lab (unreachable) ─────────────────────────────────────────────────────
    {
        "host":  "bigip-lab.example.com",
        "error": "Connection refused — device offline",
        "scale": 0,
        "virtual_servers": [],
    },
]


# ── Build manifest ─────────────────────────────────────────────────────────────

print("Generating one week of 5-minute polling data …")

irules_data: dict   = {}
device_records: list = []

for dev in DEVICES:
    if dev.get("error"):
        device_records.append({
            "host": dev["host"],
            "error": dev["error"],
            "virtual_servers": [],
        })
        continue

    scale = dev.get("scale", 1.0)
    vs_list = []

    for vs in dev["virtual_servers"]:
        rule_keys = []
        for short_name in vs["rules"]:
            partition = vs["full_path"].split("/")[1] if "/" in vs["full_path"] else "Common"
            rule_path = f"/{partition}/{short_name}"
            key = f"{dev['host']}::{rule_path}"

            if key not in irules_data:
                seed = int(content_hash(f"{dev['host']}::{short_name}")[:8], 16)
                code     = IRULES.get(short_name, "# source not available")
                history  = generate_stats_history(short_name, scale=scale, seed=seed)
                latest   = history[-1]
                stats = {
                    "total_executions": latest["total_executions"],
                    "failures":  sum(h["failures"] for h in history),
                    "aborts":    sum(h["aborts"]   for h in history),
                    "events":    {},
                }
                analysis_text = AI_ANALYSES.get(short_name)
                irules_data[key] = {
                    "host":        dev["host"],
                    "path":        rule_path,
                    "file":        f"irule_output/{dev['host'].replace('.','_')}__{short_name}.tcl",
                    "code":        code,
                    "content_hash": content_hash(code),
                    "duplicate_keys": [],
                    "orphan":      False,
                    "stats":       stats,
                    "stats_history": history,
                    "xc_library":  None,
                    "ai_analysis": {
                        "status":   "success" if analysis_text else "failed",
                        "analysis": analysis_text or "Analysis not available.",
                        "provider": None,
                        "model":    None,
                    },
                    "ai_analysis_file": None,
                }
            rule_keys.append(key)

        vs_list.append({
            "name":      vs["name"],
            "full_path": vs["full_path"],
            "partition": vs["full_path"].split("/")[1] if "/" in vs["full_path"] else "Common",
            "rule_keys": rule_keys,
        })

    device_records.append({"host": dev["host"], "error": None,
                            "virtual_servers": vs_list})

find_duplicate_irules(irules_data)

for entry in irules_data.values():
    entry["irule_status"] = compute_irule_status(entry)

manifest = {"devices": device_records, "irules": irules_data}

out = Path("irule_output")
out.mkdir(exist_ok=True)

conn = open_db(out)
init_db(conn)

# ── Seed ServiceNow references into the DB ────────────────────────────────────
# One row per unique content_hash × ticket. INSERT OR IGNORE is safe on re-run.
now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
seen_hashes: set[str] = set()
snow_count = 0
for entry in irules_data.values():
    chash     = entry.get("content_hash")
    short_key = entry["path"].rsplit("/", 1)[-1]   # e.g. "irule_xff_insert"
    tickets   = SERVICENOW_REFS.get(short_key, [])
    if not chash or not tickets or chash in seen_hashes:
        continue
    seen_hashes.add(chash)
    for t in tickets:
        conn.execute(
            "INSERT OR IGNORE INTO servicenow_refs "
            "(content_hash, irule_path, ticket_number, ticket_type, "
            " context_snippet, llm_summary, found_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (chash, entry["path"], t["ticket_number"], t["ticket_type"],
             t.get("context_snippet"), t.get("llm_summary"), now_iso),
        )
        snow_count += 1
conn.commit()
print(f"  {snow_count} ServiceNow reference(s) seeded into DB")

import json as _json
manifest_path = out / "manifest.json"
manifest_path.write_text(_json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

viewer = out / "irule_viewer.html"
viewer.write_text(build_html(manifest, conn), encoding="utf-8")
conn.close()

total_pts = sum(len(e["stats_history"]) for e in irules_data.values())
unique_irules = len({e["content_hash"] for e in irules_data.values()})
print(f"  {len(DEVICES)} devices · {len(irules_data)} iRule instances "
      f"({unique_irules} unique) · {total_pts:,} stat data points")
print(f"Demo viewer → {viewer.resolve()}")
print(f"Open with:    open '{viewer.resolve()}'")
