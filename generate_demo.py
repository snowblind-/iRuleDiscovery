#!/usr/bin/env python3
"""
Generates a demo irule_viewer.html using synthetic multi-device data.
No BIG-IP required. Run: python generate_demo.py
"""

from pathlib import Path
from irule_discovery import build_html, irule_key, content_hash, find_duplicate_irules

AI_ANALYSES = {
    "irule_xff_insert": "This iRule inserts an X-Forwarded-For header containing the client IP address before each HTTP request reaches the pool.\n\n**Migration Recommendation:** In F5 Distributed Cloud, this functionality is natively available via the HTTP Load Balancer's 'Add X-Forwarded-For header' setting under Request/Response Headers. No custom iRule is required.\n\n**Risk:** Low. Standard header manipulation with no side effects.\n\n**Action:** Replace with built-in XC header configuration.",
    "irule_ssl_redirect": "This iRule performs an HTTP-to-HTTPS redirect on port 80 by examining the TCP local port and issuing a 301 redirect.\n\n**Migration Recommendation:** F5 XC HTTP Load Balancers support automatic HTTP-to-HTTPS redirect natively. Enable 'HTTP redirect to HTTPS' in the Load Balancer TLS settings.\n\n**Risk:** Low.\n\n**Action:** Replace with XC built-in redirect. No custom logic needed.",
    "irule_rate_limit": "This iRule implements a per-client-IP connection rate limiter using the BIG-IP table subsystem. It caps connections at 100 per 60-second window and rejects excess traffic with a TCP RST.\n\n**Migration Recommendation:** F5 XC provides rate limiting natively through Service Policies. Configure an IP-based rate limit rule in the App Firewall or Service Policy attached to the Load Balancer.\n\n**Risk:** Medium. Verify rate limit thresholds match current tuning before cutover.\n\n**Action:** Migrate to XC Service Policy rate limiting rule.",
    "irule_jwt_validate": "This iRule validates the presence of a Bearer token in the Authorization header and rejects requests without one with a 401 response. It also forwards the raw token as an upstream header hint.\n\n**Migration Recommendation:** F5 XC supports JWT validation natively via Service Policies with 'JWT Claims' match conditions and OAuth/OIDC integration.\n\n**Risk:** High. Ensure the upstream header forwarding (X-Token-Hint) is replicated in XC header rules if the backend depends on it.\n\n**Action:** Configure XC JWT validation policy. Map X-Token-Hint using a custom request header rule.",
    "irule_maintenance_page": "This iRule returns a static 503 maintenance page when all pool members are unavailable.\n\n**Migration Recommendation:** F5 XC supports custom error responses via the HTTP Load Balancer 'Error Response' configuration. A static 503 page can be returned without any custom logic.\n\n**Risk:** Low.\n\n**Action:** Configure XC custom error page for 503 status.",
    "irule_geo_block": "This iRule blocks requests from countries listed in a data group (blocked_countries) using the whereis command for IP geolocation.\n\n**Migration Recommendation:** F5 XC includes built-in geo-filtering via App Firewall and Service Policies. Country-based blocking is available as a native policy match condition.\n\n**Risk:** Low. Verify country codes are consistent between BIG-IP and XC geolocation databases.\n\n**Action:** Migrate to XC Service Policy with 'Country' match condition.",
}

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

# Two synthetic BIG-IP devices
DEVICES = [
    {
        "host": "bigip-dc1.example.com",
        "virtual_servers": [
            {
                "name": "vs_web_443",
                "full_path": "/Common/vs_web_443",
                "partition": "Common",
                "rules": ["irule_xff_insert", "irule_ssl_redirect", "irule_rate_limit"],
            },
            {
                "name": "vs_api_8443",
                "full_path": "/Common/vs_api_8443",
                "partition": "Common",
                "rules": ["irule_jwt_validate", "irule_rate_limit"],
            },
            {
                "name": "vs_legacy_80",
                "full_path": "/Common/vs_legacy_80",
                "partition": "Common",
                "rules": ["irule_ssl_redirect", "irule_maintenance_page"],
            },
        ],
    },
    {
        "host": "bigip-dc2.example.com",
        "virtual_servers": [
            {
                "name": "vs_public_443",
                "full_path": "/Common/vs_public_443",
                "partition": "Common",
                "rules": ["irule_geo_block", "irule_xff_insert", "irule_rate_limit"],
            },
            {
                "name": "vs_internal_api",
                "full_path": "/Prod/vs_internal_api",
                "partition": "Prod",
                "rules": ["irule_jwt_validate"],
            },
        ],
    },
]

# Build manifest in the same format the real script produces
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
                code = IRULES.get(short_name, "# source not available")
                irules_data[key] = {
                    "host": dev["host"],
                    "path": rule_path,
                    "file": f"irule_output/irules/{dev['host'].replace('.','_')}__{short_name}.tcl",
                    "code": code,
                    "content_hash": content_hash(code),
                    "duplicate_keys": [],
                    "ai_analysis": {
                        "status": "success" if analysis_text else "failed",
                        "analysis": analysis_text or "Analysis not available for this rule.",
                    },
                    "ai_analysis_file": f"irule_output/irules/{dev['host'].replace('.','_')}__{short_name}.analysis.txt" if analysis_text else None,
                }
            rule_keys.append(key)
        vs_list.append({
            "name": vs["name"],
            "full_path": vs["full_path"],
            "partition": vs["partition"],
            "rule_keys": rule_keys,
        })
    device_records.append({"host": dev["host"], "error": None, "virtual_servers": vs_list})

find_duplicate_irules(irules_data)
manifest = {"devices": device_records, "irules": irules_data}

out = Path("irule_output")
out.mkdir(exist_ok=True)
viewer = out / "irule_viewer.html"
viewer.write_text(build_html(manifest), encoding="utf-8")
print(f"Demo viewer → {viewer.resolve()}")
print(f"Open with:    open '{viewer.resolve()}'")
