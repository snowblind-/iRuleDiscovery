#!/usr/bin/env python3
"""
iRule Discovery Tool — queries one or more BIG-IP devices for virtual servers and
their attached iRules, saves each iRule as a .tcl file, and generates a
self-contained HTML diagram viewer with a three-tier hierarchy:
  Device → Virtual Servers → iRules

Optional F5 Distributed Cloud integration:
  --xc-tenant / --xc-namespace / --xc-api-token
    Upload each discovered iRule to an XC tenant and query the XC AI assistant
    for an analysis. Results are embedded in the HTML viewer.
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sqlite3
import sys
import time
import webbrowser
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _load_env_file(path: Path | None = None) -> None:
    """
    Load a .env file into os.environ (only sets variables not already set).
    Looks for .env in the script's directory by default.
    Lines starting with # are comments; blank lines are skipped.
    """
    env_path = path or (Path(__file__).parent / ".env")
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key   = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_env_file()


# F5 Distributed Cloud REST endpoints
_XC_BASE          = "https://{tenant}.console.ves.volterra.io"
_XC_AI_URL        = _XC_BASE + "/api/gen-ai/namespaces/{namespace}/query"
_XC_IRULE_URL     = _XC_BASE + "/api/config/namespaces/{namespace}/irules"

# Source label stamped on every iRule uploaded by this tool
_IRD_SOURCE_LABEL = "irule-discovery"

# Legacy JSON file names (kept only for one-time migration to SQLite)
_REGISTRY_FILE    = "upload_registry.json"
_AI_CACHE_FILE    = "ai_analysis_cache.json"

# SQLite database (single file, replaces both JSON registries)
_DB_FILE          = "irule_discovery.db"

# Minimum seconds between AI query requests (XC rate-limit guidance)
_XC_AI_RATE_LIMIT = 20


# ── BIG-IP API helpers ────────────────────────────────────────────────────────

def get_token(session: requests.Session, host: str, username: str, password: str) -> str:
    url = f"https://{host}/mgmt/shared/authn/login"
    resp = session.post(url, json={
        "username": username,
        "password": password,
        "loginProviderName": "tmos",
    }, timeout=30)
    resp.raise_for_status()
    return resp.json()["token"]["token"]


def get_virtual_servers(session: requests.Session, host: str) -> list[dict]:
    url = f"https://{host}/mgmt/tm/ltm/virtual"
    resp = session.get(url, params={"expandSubcollections": "true"}, timeout=30)
    resp.raise_for_status()
    return resp.json().get("items", [])


def _decode_bigip_string(s: str) -> str:
    """
    BIG-IP iControl REST returns apiAnonymous with JSON-style escape sequences
    (literal \\n, \\t, \\") instead of actual characters.  Decode one level.
    Process \\\\ first so we don't double-convert it.
    """
    return (s
            .replace('\\\\', '\x00')   # protect literal backslash temporarily
            .replace('\\n',  '\n')
            .replace('\\t',  '\t')
            .replace('\\r',  '\r')
            .replace('\\"',  '"')
            .replace('\x00', '\\'))    # restore literal backslash


def get_irule_content(session: requests.Session, host: str, rule_path: str) -> str:
    """Fetch iRule TCL source. rule_path is like /Common/my_rule."""
    encoded = rule_path.replace("/", "~")
    url = f"https://{host}/mgmt/tm/ltm/rule/{encoded}"
    resp = session.get(url, timeout=30)
    resp.raise_for_status()
    raw = resp.json().get("apiAnonymous", "")
    return _decode_bigip_string(raw)


def get_all_irule_paths(session: requests.Session, host: str,
                        partition: str | None = None) -> list[str]:
    """Return fullPath of every iRule defined on the device (for orphan detection)."""
    url    = f"https://{host}/mgmt/tm/ltm/rule"
    params: dict = {"$select": "fullPath,partition"}
    resp = session.get(url, params=params, timeout=30)
    resp.raise_for_status()
    paths = [item["fullPath"] for item in resp.json().get("items", [])]
    if partition:
        paths = [p for p in paths if p.split("/")[1] == partition
                 if len(p.split("/")) > 1]
    return paths


def get_irule_stats(session: requests.Session, host: str,
                    rule_path: str) -> dict:
    """
    Fetch execution statistics for one iRule from BIG-IP.
    Aggregates across all events.
    Returns {"total_executions": int, "failures": int, "aborts": int, "events": dict}.
    """
    encoded = rule_path.replace("/", "~")
    url     = f"https://{host}/mgmt/tm/ltm/rule/{encoded}/stats"
    try:
        resp = session.get(url, timeout=30)
        if not resp.ok:
            return {"total_executions": 0, "failures": 0, "aborts": 0, "events": {}}
        total_exec = 0; failures = 0; aborts = 0; events: dict = {}
        for entry_key, entry_val in resp.json().get("entries", {}).items():
            nested = entry_val.get("nestedStats", {}).get("entries", {})
            ev = entry_key.rsplit(":", 1)[-1] if ":" in entry_key else entry_key
            t  = nested.get("totalExecutions", {}).get("value", 0)
            f  = nested.get("failures",        {}).get("value", 0)
            a  = nested.get("aborts",          {}).get("value", 0)
            total_exec += t; failures += f; aborts += a
            events[ev] = {"total_executions": t, "failures": f, "aborts": a}
        return {"total_executions": total_exec, "failures": failures,
                "aborts": aborts, "events": events}
    except Exception:
        return {"total_executions": 0, "failures": 0, "aborts": 0, "events": {}}


# ── AI analysis — multi-provider ─────────────────────────────────────────────

# Default models per provider
_AI_DEFAULT_MODELS = {
    "xc":        None,                   # XC has no model selection
    "anthropic":  "claude-sonnet-4-6",
    "openai":     "gpt-4o",
}

# Structured analysis prompt — same for all providers
_ANALYSIS_PROMPT = """\
Analyse the following F5 BIG-IP iRule and respond with exactly these three sections using Markdown headings:

## 1. Objective
State the primary purpose of this iRule — what it is designed to do and what problem or requirement it addresses.

## 2. Execution Flow
Describe step by step what happens when this iRule executes: which events trigger it, what conditions are evaluated, what variables are set, and what actions are taken.

## 3. Recommendations
Provide specific, actionable recommendations focused entirely on improving this iRule as BIG-IP TCL code. Consider:
- Logic correctness and edge cases that are not handled
- TCL coding best practices and efficiency improvements (e.g. avoid redundant commands, prefer built-in over custom logic)
- Event selection — is this the most appropriate event, or would a different event be more efficient?
- Performance — unnecessary work per request, commands that should be cached in variables, table/datagroup lookups that could be optimised
- Security — input validation, header sanitisation, injection risks
- Resilience — what happens if expected values are absent or malformed
- Readability and maintainability of the TCL code

Do NOT recommend migrating to any other platform or product. All recommendations must apply to this iRule running on BIG-IP.

---
iRule source:
```tcl
{code}
```"""


def _truncate_code(code: str, max_chars: int) -> str:
    if len(code) <= max_chars:
        return code
    return (code[:max_chars]
            + f"\n\n# ... truncated at {max_chars} chars "
              f"({len(code) - max_chars} chars omitted)")


def _analyze_with_xc(ai_cfg: dict, code: str, max_retries: int = 3) -> dict:
    """F5 Distributed Cloud Gen-AI backend."""
    query_code = _truncate_code(code, ai_cfg.get("max_query_chars", 8000))
    url     = _XC_AI_URL.format(tenant=ai_cfg["tenant"], namespace=ai_cfg["namespace"])
    headers = {"Authorization": f"APIToken {ai_cfg['api_key']}", "Content-Type": "application/json"}
    payload = {"current_query": _ANALYSIS_PROMPT.format(code=query_code),
               "namespace": ai_cfg["namespace"]}
    retry_on = {429, 500, 503, 504}
    log = logging.getLogger(__name__)

    for attempt in range(1, max_retries + 1):
        try:
            log.debug("XC AI → %s (attempt %d)", url, attempt)
            resp = requests.post(url, headers=headers, json=payload, timeout=60)
            log.debug("XC AI status=%d body=%s", resp.status_code, resp.text[:400])
            if resp.status_code in retry_on and attempt < max_retries:
                wait = 2 ** attempt
                print(f" (retry {wait}s)", end="", flush=True)
                time.sleep(wait); continue
            resp.raise_for_status()
            data    = resp.json()
            generic = data.get("generic_response", {})
            if generic.get("is_error"):
                detail = generic.get("error") or json.dumps(generic, indent=2)
                return {"status": "failed", "analysis": f"AI error: {detail}"}
            return {"status": "success", "analysis": generic.get("summary", json.dumps(data, indent=2))}
        except requests.HTTPError as exc:
            body = exc.response.text[:400] if exc.response is not None else str(exc)
            return {"status": "failed", "analysis": f"HTTP {exc.response.status_code}: {body}"}
        except Exception as exc:
            return {"status": "failed", "analysis": str(exc)}
    return {"status": "failed", "analysis": "max retries exceeded"}


def _analyze_with_anthropic(ai_cfg: dict, code: str, max_retries: int = 3) -> dict:
    """Anthropic Claude backend (raw HTTP, no SDK required)."""
    query_code = _truncate_code(code, ai_cfg.get("max_query_chars", 8000))
    model   = ai_cfg.get("model") or _AI_DEFAULT_MODELS["anthropic"]
    url     = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key":         ai_cfg["api_key"],
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json",
    }
    payload = {
        "model":      model,
        "max_tokens": 4096,
        "messages":   [{"role": "user", "content": _ANALYSIS_PROMPT.format(code=query_code)}],
    }
    retry_on = {429, 500, 503, 529}
    log = logging.getLogger(__name__)

    for attempt in range(1, max_retries + 1):
        try:
            log.debug("Anthropic → %s model=%s (attempt %d)", url, model, attempt)
            resp = requests.post(url, headers=headers, json=payload, timeout=120)
            log.debug("Anthropic status=%d", resp.status_code)
            if resp.status_code in retry_on and attempt < max_retries:
                wait = int(resp.headers.get("retry-after", 2 ** attempt))
                print(f" (retry {wait}s)", end="", flush=True)
                time.sleep(wait); continue
            resp.raise_for_status()
            data = resp.json()
            text = data.get("content", [{}])[0].get("text", "")
            if not text:
                return {"status": "failed", "analysis": f"Empty response: {json.dumps(data)[:400]}"}
            return {"status": "success", "analysis": text}
        except requests.HTTPError as exc:
            body = exc.response.text[:400] if exc.response is not None else str(exc)
            return {"status": "failed", "analysis": f"HTTP {exc.response.status_code}: {body}"}
        except Exception as exc:
            return {"status": "failed", "analysis": str(exc)}
    return {"status": "failed", "analysis": "max retries exceeded"}


def _analyze_with_openai(ai_cfg: dict, code: str, max_retries: int = 3) -> dict:
    """OpenAI ChatCompletion backend (raw HTTP, no SDK required)."""
    query_code = _truncate_code(code, ai_cfg.get("max_query_chars", 8000))
    model   = ai_cfg.get("model") or _AI_DEFAULT_MODELS["openai"]
    url     = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {ai_cfg['api_key']}", "Content-Type": "application/json"}
    payload = {
        "model":      model,
        "max_tokens": 4096,
        "messages":   [{"role": "user", "content": _ANALYSIS_PROMPT.format(code=query_code)}],
    }
    retry_on = {429, 500, 503}
    log = logging.getLogger(__name__)

    for attempt in range(1, max_retries + 1):
        try:
            log.debug("OpenAI → %s model=%s (attempt %d)", url, model, attempt)
            resp = requests.post(url, headers=headers, json=payload, timeout=120)
            log.debug("OpenAI status=%d", resp.status_code)
            if resp.status_code in retry_on and attempt < max_retries:
                wait = int(resp.headers.get("retry-after", 2 ** attempt))
                print(f" (retry {wait}s)", end="", flush=True)
                time.sleep(wait); continue
            resp.raise_for_status()
            data = resp.json()
            text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            if not text:
                return {"status": "failed", "analysis": f"Empty response: {json.dumps(data)[:400]}"}
            return {"status": "success", "analysis": text}
        except requests.HTTPError as exc:
            body = exc.response.text[:400] if exc.response is not None else str(exc)
            return {"status": "failed", "analysis": f"HTTP {exc.response.status_code}: {body}"}
        except Exception as exc:
            return {"status": "failed", "analysis": str(exc)}
    return {"status": "failed", "analysis": "max retries exceeded"}


_PROVIDER_FN = {
    "xc":        _analyze_with_xc,
    "anthropic":  _analyze_with_anthropic,
    "openai":     _analyze_with_openai,
}


def analyze_irule(ai_cfg: dict, code: str) -> dict:
    """
    Dispatch iRule analysis to the configured provider.
    ai_cfg must contain 'provider' and 'api_key' (plus 'tenant'/'namespace' for xc).
    Returns {"status": "success"|"failed", "analysis": str, "provider": str, "model": str|None}.
    """
    provider = ai_cfg.get("provider", "xc")
    fn = _PROVIDER_FN.get(provider)
    if fn is None:
        return {"status": "failed",
                "analysis": f"Unknown AI provider '{provider}'. Choose: {', '.join(_PROVIDER_FN)}",
                "provider": provider, "model": None}
    result = fn(ai_cfg, code)
    result["provider"] = provider
    result["model"]    = ai_cfg.get("model") or _AI_DEFAULT_MODELS.get(provider)
    return result


# ── XC iRule library helpers ──────────────────────────────────────────────────

def xc_list_library_irules(tenant: str, namespace: str, api_token: str) -> dict[str, dict]:
    """
    List iRules already in the XC library that were uploaded by this tool
    (label: source=irule-discovery).  Returns {content_hash: {xc_name, xc_namespace}}.
    """
    url     = _XC_IRULE_URL.format(tenant=tenant, namespace=namespace)
    headers = {"Authorization": f"APIToken {api_token}"}
    result  = {}
    params  = {"label_filter": f"source={_IRD_SOURCE_LABEL}", "per_page": 200}

    while True:
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            if not resp.ok:
                break
            body  = resp.json()
            items = body.get("items", [])
            for item in items:
                meta  = item.get("object", item).get("metadata", {})
                annot = meta.get("annotations", {})
                chash = annot.get("irule-discovery/content-hash")
                name  = meta.get("name", "")
                if chash and name:
                    result[chash] = {"xc_name": name, "xc_namespace": namespace}
            cursor = body.get("next_page_id") or body.get("metadata", {}).get("next_page_id")
            if not cursor:
                break
            params["page_start"] = cursor
        except Exception:
            break

    return result


def xc_upload_irule(tenant: str, namespace: str, api_token: str,
                    rule_path: str, code: str, chash: str,
                    origin_host: str, max_retries: int = 3) -> dict:
    """
    Upload a single iRule to the XC library.
    Returns {"status": "success"|"failed"|"exists", "xc_name": str, "detail": str}.
    """
    import datetime
    name    = xc_irule_name(rule_path)
    url     = _XC_IRULE_URL.format(tenant=tenant, namespace=namespace)
    headers = {"Authorization": f"APIToken {api_token}", "Content-Type": "application/json"}
    payload = {
        "metadata": {
            "name":      name,
            "namespace": namespace,
            "labels":    {"source": _IRD_SOURCE_LABEL},
            "annotations": {
                "irule-discovery/origin-host":   origin_host,
                "irule-discovery/origin-path":   rule_path,
                "irule-discovery/content-hash":  chash,
                "irule-discovery/uploaded-at":   datetime.datetime.utcnow().isoformat() + "Z",
            },
        },
        "spec": {"irule": code},
    }
    retry_on = {429, 500, 503, 504}

    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=30)
            if resp.status_code == 409:
                # Name collision — a rule with this name already exists (not uploaded by us)
                return {"status": "exists", "xc_name": name,
                        "detail": "name collision — rule with that name already exists in XC"}
            if resp.status_code in retry_on and attempt < max_retries:
                time.sleep(2 ** attempt)
                continue
            resp.raise_for_status()
            return {"status": "success", "xc_name": name, "detail": ""}
        except requests.HTTPError as exc:
            body = exc.response.text[:400] if exc.response is not None else str(exc)
            return {"status": "failed", "xc_name": name,
                    "detail": f"HTTP {exc.response.status_code}: {body}"}
        except Exception as exc:
            return {"status": "failed", "xc_name": name, "detail": str(exc)}

    return {"status": "failed", "xc_name": name, "detail": "max retries exceeded"}


def xc_upload_irules(irules_data: dict, out_dir: Path, xc_cfg: dict,
                     db_conn: sqlite3.Connection) -> None:
    """
    Phase 3 — upload iRules to the XC iRules library.
    Deduplicates by content hash; registry is stored in SQLite.
    Updates each irules_data entry with a 'xc_library' field after the run.
    """
    import datetime
    tenant    = xc_cfg["tenant"]
    namespace = xc_cfg.get("upload_namespace", xc_cfg["namespace"])
    api_token = xc_cfg["api_token"]
    log       = logging.getLogger(__name__)

    entries = db_load_upload_registry(db_conn)

    # ── Sync: pull existing XC library iRules into DB ──
    print("  [XC] Scanning iRule library for existing uploads …", end=" ", flush=True)
    xc_existing = xc_list_library_irules(tenant, namespace, api_token)
    synced = 0
    for chash, info in xc_existing.items():
        if chash not in entries:
            entry_data = {**info, "source": "sync",
                          "uploaded_at": datetime.datetime.utcnow().isoformat() + "Z"}
            db_save_upload(db_conn, chash, entry_data)
            entries[chash] = entry_data
            synced += 1
    print(f"{len(xc_existing)} found in library ({synced} new to registry)")

    # ── Choose one representative per unique hash ──
    hash_to_rep: dict[str, str] = {}
    for key, entry in irules_data.items():
        chash = entry.get("content_hash")
        if not chash or not entry.get("code") or entry["code"].startswith("# fetch failed"):
            continue
        all_keys = sorted([key] + entry.get("duplicate_keys", []))
        if chash not in hash_to_rep:
            hash_to_rep[chash] = all_keys[0]

    already   = sum(1 for h in hash_to_rep if h in entries)
    to_upload = [(h, key) for h, key in hash_to_rep.items() if h not in entries]

    print(f"\n  {len(to_upload)} to upload · {already} already in registry "
          f"({len(hash_to_rep)} unique hashes total)")

    for idx, (chash, key) in enumerate(to_upload, 1):
        entry     = irules_data[key]
        rule_path = entry["path"]
        code      = entry["code"]
        host      = entry["host"]

        print(f"  [{idx}/{len(to_upload)}] {rule_path} … ", end="", flush=True)
        result = xc_upload_irule(tenant, namespace, api_token, rule_path, code, chash, host)

        if result["status"] == "success":
            print(f"ok → {result['xc_name']}")
            entry_data = {
                "xc_name":      result["xc_name"],
                "xc_namespace": namespace,
                "uploaded_at":  datetime.datetime.utcnow().isoformat() + "Z",
                "origin_host":  host,
                "origin_path":  rule_path,
                "manifest_key": key,
                "source":       _IRD_SOURCE_LABEL,
            }
            db_save_upload(db_conn, chash, entry_data)
            entries[chash] = entry_data
        elif result["status"] == "exists":
            print(f"skipped — {result['detail']}")
        else:
            print(f"FAILED — {result['detail']}")
            log.debug("upload error for %s: %s", key, result["detail"])

    # ── Back-fill xc_library on every irules_data entry ──
    entries = db_load_upload_registry(db_conn)   # re-read after any inserts
    for key, entry in irules_data.items():
        chash = entry.get("content_hash")
        entry["xc_library"] = entries.get(chash) if chash else None

    print(f"\n[+] Upload registry → {out_dir / _DB_FILE}")


# ── File helpers ──────────────────────────────────────────────────────────────

def safe_filename(host: str, rule_path: str) -> str:
    host_part = re.sub(r"[^\w\-.]", "_", host)
    rule_part = rule_path.lstrip("/").replace("/", "__")
    rule_part = re.sub(r"[^\w\-.]", "_", rule_part)
    return f"{host_part}__{rule_part}.tcl"


def analysis_filename(host: str, rule_path: str) -> str:
    return safe_filename(host, rule_path).replace(".tcl", ".analysis.txt")


def irule_key(host: str, rule_path: str) -> str:
    return f"{host}::{rule_path}"


def content_hash(code: str) -> str:
    """SHA-256 of stripped iRule source — used for cross-device duplicate detection."""
    return hashlib.sha256(code.strip().encode("utf-8")).hexdigest()


def xc_irule_name(rule_path: str) -> str:
    """
    Convert /Common/my_rule → ird--common--my-rule
    XC resource names: lowercase alphanumeric + hyphens, max 63 chars.
    """
    parts = [p for p in rule_path.lower().split("/") if p]
    raw   = "--".join(parts)
    raw   = re.sub(r"[^a-z0-9-]", "-", raw)
    raw   = re.sub(r"-{2,}", "--", raw).strip("-")
    return f"ird--{raw}"[:63]


# ── SQLite database ───────────────────────────────────────────────────────────

def open_db(out_dir: Path) -> sqlite3.Connection:
    """Open (or create) the local SQLite database with WAL mode."""
    conn = sqlite3.connect(out_dir / _DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Create tables if they don't already exist."""
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS upload_registry (
        content_hash  TEXT PRIMARY KEY,
        xc_name       TEXT NOT NULL,
        xc_namespace  TEXT NOT NULL,
        origin_host   TEXT,
        origin_path   TEXT,
        manifest_key  TEXT,
        uploaded_at   TEXT NOT NULL,
        source        TEXT DEFAULT 'irule-discovery'
    );

    CREATE TABLE IF NOT EXISTS ai_cache (
        cache_key    TEXT PRIMARY KEY,
        status       TEXT NOT NULL,
        analysis     TEXT,
        provider     TEXT,
        model        TEXT,
        analyzed_at  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS irule_stats (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        content_hash      TEXT NOT NULL,
        host              TEXT NOT NULL,
        rule_path         TEXT NOT NULL,
        run_at            TEXT NOT NULL,
        total_executions  INTEGER NOT NULL DEFAULT 0,
        failures          INTEGER NOT NULL DEFAULT 0,
        aborts            INTEGER NOT NULL DEFAULT 0,
        events_json       TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_stats_hash ON irule_stats(content_hash, run_at);

    CREATE TABLE IF NOT EXISTS servicenow_refs (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        content_hash     TEXT NOT NULL,
        irule_path       TEXT NOT NULL,
        ticket_number    TEXT NOT NULL,
        ticket_type      TEXT NOT NULL,
        context_snippet  TEXT,
        llm_summary      TEXT,
        found_at         TEXT NOT NULL,
        UNIQUE(content_hash, ticket_number)
    );
    """)
    conn.commit()


def _migrate_json_to_db(conn: sqlite3.Connection, out_dir: Path) -> None:
    """One-time migration of legacy JSON files into the SQLite DB."""
    import datetime
    now = datetime.datetime.utcnow().isoformat() + "Z"

    reg_path = out_dir / _REGISTRY_FILE
    if reg_path.exists():
        try:
            data = json.loads(reg_path.read_text(encoding="utf-8"))
            for chash, e in data.get("entries", {}).items():
                conn.execute(
                    "INSERT OR IGNORE INTO upload_registry "
                    "(content_hash,xc_name,xc_namespace,origin_host,origin_path,"
                    " manifest_key,uploaded_at,source) VALUES (?,?,?,?,?,?,?,?)",
                    (chash, e.get("xc_name",""), e.get("xc_namespace",""),
                     e.get("origin_host"), e.get("origin_path"),
                     e.get("manifest_key"), e.get("uploaded_at", now),
                     e.get("source", _IRD_SOURCE_LABEL)))
            conn.commit()
            reg_path.rename(reg_path.with_suffix(".json.migrated"))
            print(f"[~] Migrated {reg_path.name} → upload_registry table")
        except Exception as exc:
            logging.getLogger(__name__).debug("upload_registry migration error: %s", exc)

    cache_path = out_dir / _AI_CACHE_FILE
    if cache_path.exists():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            for ckey, e in data.get("entries", {}).items():
                conn.execute(
                    "INSERT OR IGNORE INTO ai_cache "
                    "(cache_key,status,analysis,provider,model,analyzed_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (ckey, e.get("status",""), e.get("analysis",""),
                     e.get("provider"), e.get("model"), now))
            conn.commit()
            cache_path.rename(cache_path.with_suffix(".json.migrated"))
            print(f"[~] Migrated {cache_path.name} → ai_cache table")
        except Exception as exc:
            logging.getLogger(__name__).debug("ai_cache migration error: %s", exc)


def db_load_upload_registry(conn: sqlite3.Connection) -> dict:
    """Return {content_hash: entry_dict} for all uploaded iRules."""
    return {row["content_hash"]: dict(row)
            for row in conn.execute("SELECT * FROM upload_registry").fetchall()}


def db_save_upload(conn: sqlite3.Connection, chash: str, entry: dict) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO upload_registry "
        "(content_hash,xc_name,xc_namespace,origin_host,origin_path,"
        " manifest_key,uploaded_at,source) VALUES (?,?,?,?,?,?,?,?)",
        (chash, entry.get("xc_name",""), entry.get("xc_namespace",""),
         entry.get("origin_host"), entry.get("origin_path"),
         entry.get("manifest_key"), entry.get("uploaded_at",""),
         entry.get("source", _IRD_SOURCE_LABEL)))
    conn.commit()


def _ai_cache_key(content_hash_val: str, provider: str, model: str | None) -> str:
    """Stable lookup key for the ai_cache table."""
    return f"{content_hash_val}::{provider}::{model or ''}"


def db_get_ai_result(conn: sqlite3.Connection, cache_key: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM ai_cache WHERE cache_key=?", (cache_key,)).fetchone()
    return dict(row) if row else None


def db_save_ai_result(conn: sqlite3.Connection, cache_key: str,
                      result: dict) -> None:
    import datetime
    conn.execute(
        "INSERT OR REPLACE INTO ai_cache "
        "(cache_key,status,analysis,provider,model,analyzed_at) "
        "VALUES (?,?,?,?,?,?)",
        (cache_key, result.get("status",""), result.get("analysis",""),
         result.get("provider"), result.get("model"),
         datetime.datetime.utcnow().isoformat()+"Z"))
    conn.commit()


def db_record_stats(conn: sqlite3.Connection, content_hash: str, host: str,
                    rule_path: str, run_at: str, total_executions: int,
                    failures: int, aborts: int,
                    events_json: str | None = None) -> None:
    conn.execute(
        "INSERT INTO irule_stats "
        "(content_hash,host,rule_path,run_at,total_executions,failures,aborts,events_json) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (content_hash, host, rule_path, run_at,
         total_executions, failures, aborts, events_json))
    conn.commit()


def db_get_stats_history(conn: sqlite3.Connection, content_hash: str,
                         limit: int = 100) -> list[dict]:
    """
    Return the last `limit` stat snapshots for a content hash, oldest first.
    Each entry includes delta_executions = executions since the previous snapshot,
    giving a rate-per-interval view rather than a monotone cumulative counter.
    Counter resets (device reboot) are clamped to 0.
    """
    rows = conn.execute(
        "SELECT run_at, total_executions, failures, aborts FROM irule_stats "
        "WHERE content_hash=? ORDER BY run_at DESC LIMIT ?",
        (content_hash, limit)).fetchall()
    history = [dict(r) for r in reversed(rows)]
    for i, entry in enumerate(history):
        prev = history[i - 1]["total_executions"] if i > 0 else entry["total_executions"]
        entry["delta_executions"] = max(0, entry["total_executions"] - prev)
    return history


def load_hosts_file(path: str) -> list[str]:
    hosts = []
    for line in Path(path).read_text().splitlines():
        line = line.split("#")[0].strip()
        if line:
            hosts.append(line)
    if not hosts:
        sys.exit(f"[!] No hosts found in {path}")
    return hosts


# ── Per-device discovery ──────────────────────────────────────────────────────

def discover_device(host: str, username: str, password: str,
                    partition: str | None,
                    irules_dir: Path,
                    irules_data: dict,
                    include_orphans: bool = False) -> dict:
    """
    Phase 1 — connect to one BIG-IP, collect VS→iRule inventory, save .tcl files.
    No rate limiting; downloads run as fast as the device allows.
    Returns a device record for the manifest.
    """
    session = requests.Session()
    session.verify = False

    print(f"\n[*] Connecting to https://{host} …")
    try:
        token = get_token(session, host, username, password)
    except requests.HTTPError as exc:
        msg = f"authentication failed ({exc.response.status_code})"
        print(f"[!] {host}: {msg}")
        return {"host": host, "error": msg, "virtual_servers": []}
    except Exception as exc:
        print(f"[!] {host}: {exc}")
        return {"host": host, "error": str(exc), "virtual_servers": []}

    session.headers.update({"X-F5-Auth-Token": token})
    print(f"[+] {host}: authenticated")

    try:
        raw_vs = get_virtual_servers(session, host)
    except Exception as exc:
        msg = f"failed to fetch virtual servers: {exc}"
        print(f"[!] {host}: {msg}")
        return {"host": host, "error": msg, "virtual_servers": []}

    if partition:
        raw_vs = [v for v in raw_vs if v.get("partition") == partition]

    print(f"[+] {host}: {len(raw_vs)} virtual server(s)")

    vs_list: list[dict] = []
    all_rule_paths: set[str] = set()

    for vs in raw_vs:
        rule_refs = vs.get("rules", [])
        rules = []
        for r in rule_refs:
            full = r if r.startswith("/") else f"/{vs.get('partition', 'Common')}/{r}"
            rules.append(full)
            all_rule_paths.add(full)
        vs_list.append({
            "name": vs.get("name", ""),
            "full_path": vs.get("fullPath", vs.get("name", "")),
            "partition": vs.get("partition", "Common"),
            "rule_keys": [irule_key(host, r) for r in rules],
        })

    print(f"[+] {host}: {len(all_rule_paths)} unique iRule(s) attached to VS")

    # ── Orphan detection (opt-in via --include-orphans) ─────────────────────
    orphan_paths: set[str] = set()
    if include_orphans:
        try:
            device_paths = get_all_irule_paths(session, host, partition)
            # Strip BIG-IP built-in system iRules (_sys_* prefix on the name
            # component, e.g. /Common/_sys_https_redirect).  These are shipped
            # by F5 and are never user-defined; including them inflates the count
            # with hundreds of rules the user has no interest in analysing.
            user_paths = {p for p in device_paths
                          if not p.rsplit("/", 1)[-1].startswith("_sys_")}
            orphan_paths = user_paths - all_rule_paths
            if orphan_paths:
                print(f"[+] {host}: {len(orphan_paths)} orphan iRule(s) not attached to any VS")
        except Exception as exc:
            logging.getLogger(__name__).debug("Orphan detection failed for %s: %s", host, exc)

    # ── Fetch code + stats for VS-attached rules (+ orphans if opted in) ────
    for rule_path in sorted(all_rule_paths | orphan_paths):
        key       = irule_key(host, rule_path)
        is_orphan = rule_path in orphan_paths

        if key not in irules_data:
            print(f"  [*] {host}: fetching {rule_path} …", end=" ", flush=True)
            try:
                code = get_irule_content(session, host, rule_path)
            except requests.HTTPError as exc:
                print(f"FAILED ({exc.response.status_code})")
                irules_data[key] = {
                    "host": host, "path": rule_path, "file": None,
                    "code": f"# fetch failed ({exc.response.status_code})",
                    "content_hash": None, "duplicate_keys": [],
                    "ai_analysis": None, "ai_analysis_file": None,
                    "orphan": is_orphan, "stats": None,
                    "irule_status": "orphan" if is_orphan else "attached",
                    "stats_history": [],
                }
                continue

            fname = safe_filename(host, rule_path)
            fpath = irules_dir / fname
            fpath.write_text(code, encoding="utf-8")
            print(f"saved → {fpath.name}")

            irules_data[key] = {
                "host": host, "path": rule_path,
                "file": str(fpath), "code": code,
                "content_hash": content_hash(code), "duplicate_keys": [],
                "ai_analysis": None, "ai_analysis_file": None,
                "orphan": is_orphan, "stats": None,
                "irule_status": "attached", "stats_history": [],
            }
        else:
            # Already fetched from another VS; keep orphan=False if any VS uses it
            irules_data[key]["orphan"] = (is_orphan
                                          and irules_data[key].get("orphan", False))

        # Fetch execution stats regardless of orphan status
        irules_data[key]["stats"] = get_irule_stats(session, host, rule_path)

    return {"host": host, "error": None, "virtual_servers": vs_list}


def ai_enrich_irules(irules_data: dict, irules_dir: Path, ai_cfg: dict,
                     db_conn: sqlite3.Connection) -> None:
    """
    Phase 2 — query the configured AI provider for each downloaded iRule.
    Skips iRules whose content hash is already cached in the DB for this
    provider/model.  Writes each new successful result to the DB immediately.
    """
    provider = ai_cfg.get("provider", "xc")
    model    = ai_cfg.get("model") or _AI_DEFAULT_MODELS.get(provider)
    label    = f"{provider}" + (f"/{model}" if model else "")

    keys  = [k for k, v in irules_data.items() if v.get("file")]
    total = len(keys)

    # Split into cached vs needs-query
    to_query: list[tuple[str, str | None]] = []
    for key in keys:
        entry = irules_data[key]
        chash = entry.get("content_hash")
        ckey  = _ai_cache_key(chash, provider, model) if chash else None
        cached = db_get_ai_result(db_conn, ckey) if ckey else None
        if cached:
            entry["ai_analysis"] = {
                "status":   cached["status"],
                "analysis": cached["analysis"],
                "provider": cached["provider"],
                "model":    cached["model"],
            }
        else:
            to_query.append((key, ckey))

    cached_count = total - len(to_query)
    print(f"\n[AI] {label} — {total} iRule(s): "
          f"{cached_count} cached, {len(to_query)} to query")

    if not to_query:
        return

    rate_limit   = ai_cfg.get("rate_limit", _XC_AI_RATE_LIMIT if provider == "xc" else 0)
    last_ai_call: float = 0.0

    for idx, (key, ckey) in enumerate(to_query, 1):
        entry     = irules_data[key]
        rule_path = entry["path"]
        code      = entry["code"]
        host      = entry["host"]

        print(f"  [{idx}/{len(to_query)}] {rule_path}")

        elapsed = time.time() - last_ai_call
        if last_ai_call and elapsed < rate_limit:
            wait = rate_limit - elapsed
            print(f"    [AI] rate-limit pause {wait:.1f}s …")
            time.sleep(wait)

        chars = len(code)
        lines = code.count("\n") + 1
        max_q = ai_cfg.get("max_query_chars", 8000)
        trunc_note = f", truncating to {max_q}" if chars > max_q else ""
        print(f"    [AI] querying … ({lines} lines, {chars} chars{trunc_note})",
              end=" ", flush=True)
        ai_result    = analyze_irule(ai_cfg, code)
        last_ai_call = time.time()
        entry["ai_analysis"] = ai_result

        if ai_result["status"] == "success":
            print("success")
            afname = analysis_filename(host, rule_path)
            afpath = irules_dir / afname
            afpath.write_text(ai_result["analysis"], encoding="utf-8")
            entry["ai_analysis_file"] = str(afpath)
            if ckey:
                db_save_ai_result(db_conn, ckey, ai_result)
        else:
            print(f"FAILED\n         {ai_result['analysis']}")


def collect_irule_stats(host: str, username: str, password: str,
                        out_dir: Path, partition: str | None = None,
                        db_conn: sqlite3.Connection | None = None) -> dict:
    """
    Standalone stats refresh for a single BIG-IP device.

    Connects to the device, fetches execution stats for every iRule (attached
    and orphaned), compares the content hash against the last recorded run, and
    only records a new DB row when the stats have actually changed.

    Can be called independently — does NOT require a full discovery run.

    Returns a summary dict:
        {
          "host": str,
          "checked": int,          # total iRules examined
          "updated": int,          # iRules whose stats changed
          "unchanged": int,        # iRules with identical stats to last run
          "new": int,              # iRules seen for the first time
          "errors": int,           # iRules with failures or aborts
        }
    """
    import datetime

    close_conn = db_conn is None
    if db_conn is None:
        out_dir.mkdir(parents=True, exist_ok=True)
        db_conn = open_db(out_dir)
        init_db(db_conn)

    session = requests.Session()
    session.verify = False

    summary = {"host": host, "checked": 0, "updated": 0,
               "unchanged": 0, "new": 0, "errors": 0}
    run_at  = datetime.datetime.utcnow().isoformat() + "Z"

    try:
        token = get_token(session, host, username, password)
    except Exception as exc:
        summary["error"] = str(exc)
        if close_conn:
            db_conn.close()
        return summary

    session.headers.update({"X-F5-Auth-Token": token})

    try:
        all_paths = get_all_irule_paths(session, host, partition)
    except Exception as exc:
        summary["error"] = f"Could not list iRules: {exc}"
        if close_conn:
            db_conn.close()
        return summary

    for rule_path in sorted(all_paths):
        summary["checked"] += 1
        stats = get_irule_stats(session, host, rule_path)

        # Derive the content hash if the .tcl file exists in the DB history;
        # otherwise use rule_path as a proxy key for the "last seen" query.
        # (A full content hash requires fetching the source — we avoid that here.)
        # Instead, record stats keyed by a path-hash so we can compare delta.
        path_hash = hashlib.sha256(
            f"{host}::{rule_path}".encode("utf-8")).hexdigest()

        last = db_conn.execute(
            "SELECT total_executions, failures, aborts FROM irule_stats "
            "WHERE content_hash=? ORDER BY run_at DESC LIMIT 1",
            (path_hash,)).fetchone()

        changed = (last is None or
                   last["total_executions"] != stats["total_executions"] or
                   last["failures"]         != stats["failures"] or
                   last["aborts"]           != stats["aborts"])

        if last is None:
            summary["new"] += 1
        elif changed:
            summary["updated"] += 1
        else:
            summary["unchanged"] += 1

        if changed:
            db_record_stats(db_conn, path_hash, host, rule_path, run_at,
                            stats["total_executions"], stats["failures"],
                            stats["aborts"], json.dumps(stats.get("events", {})))

        if stats["failures"] > 0 or stats["aborts"] > 0:
            summary["errors"] += 1

    if close_conn:
        db_conn.close()
    return summary


def compute_irule_status(entry: dict) -> str:
    """
    Derive a single status string from an iRule manifest entry.

    error    — any failures or aborts recorded
    orphan   — exists on BIG-IP but not attached to any virtual server
    active   — attached to a VS and has at least one execution
    attached — attached to a VS but zero executions yet
    """
    stats = entry.get("stats") or {}
    if stats.get("failures", 0) > 0 or stats.get("aborts", 0) > 0:
        return "error"
    if entry.get("orphan", False):
        return "orphan"
    if stats.get("total_executions", 0) > 0:
        return "active"
    return "attached"


def find_duplicate_irules(irules_data: dict) -> int:
    """
    Group iRules by content_hash and populate each entry's duplicate_keys list.
    Returns the number of iRules that have at least one duplicate.
    """
    hash_to_keys: dict[str, list[str]] = {}
    for key, entry in irules_data.items():
        h = entry.get("content_hash")
        if h:
            hash_to_keys.setdefault(h, []).append(key)

    dup_count = 0
    for keys in hash_to_keys.values():
        if len(keys) > 1:
            for key in keys:
                irules_data[key]["duplicate_keys"] = [k for k in keys if k != key]
                dup_count += 1
    return dup_count


# ── HTML generation ───────────────────────────────────────────────────────────

HTML_TEMPLATE = r"""<!DOCTYPE html>
<!-- v2 -->
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BIG-IP iRule Discovery</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/d3-sankey@0.12.3/dist/d3-sankey.min.js"></script>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #e2e8f0; height: 100vh; display: flex; flex-direction: column; }

  header { padding: 12px 24px; background: #1a1d2e; border-bottom: 1px solid #2d3148; display: flex; align-items: center; gap: 12px; flex-shrink: 0; }
  header h1 { font-size: 1.05rem; font-weight: 600; color: #a78bfa; }
  #summary { font-size: 0.72rem; color: #4b5563; margin-left: auto; display: flex; }
  .stat-pill { display: flex; flex-direction: column; align-items: center; padding: 2px 18px;
               border-left: 1px solid #2d3148; line-height: 1.4; }
  .stat-pill:last-child { border-right: 1px solid #2d3148; }
  .stat-val { font-size: 1.05rem; font-weight: 700; color: #e2e8f0; }
  .stat-val.accent-purple { color: #a78bfa; }
  .stat-val.accent-blue   { color: #60a5fa; }
  .stat-val.accent-green  { color: #4ade80; }
  .stat-val.accent-amber  { color: #fbbf24; }
  .stat-val.accent-red    { color: #f87171; }
  .stat-lbl { font-size: 0.62rem; color: #4b5563; text-transform: uppercase; letter-spacing: 0.04em; white-space: nowrap; }

  .main-area    { display: flex; flex: 1; overflow: hidden; }
  .diagram-area { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-width: 0; }
  #pane-force   { flex: 1; display: none; overflow: hidden; }

  /* ── Resize handles ── */
  .resize-v { width: 5px; flex-shrink: 0; cursor: col-resize; background: #2d3148; position: relative; z-index: 5; transition: background 0.15s; }
  .resize-v::after { content: ''; position: absolute; inset: 0; margin: auto; width: 1px; height: 32px; background: #4b5563; border-radius: 2px; top: 50%; transform: translateY(-50%); }
  .resize-v:hover, .resize-v.dragging { background: #a78bfa; }
  .resize-v:hover::after, .resize-v.dragging::after { background: #c4b5fd; }

  /* ── Graph panel ── */
  #graph-panel { flex: 1; position: relative; overflow: hidden; }
  #graph-panel svg { width: 100%; height: 100%; }

  .link { stroke-width: 1.5px; fill: none; }
  .link.dev-vs  { stroke: #4b3f72; }
  .link.vs-rule { stroke: #1e3d2f; }
  .link.highlighted { stroke: #a78bfa !important; stroke-width: 2.5px; }

  .node { cursor: pointer; }
  .node circle { stroke-width: 2px; transition: filter 0.15s; }
  .node circle:hover { filter: brightness(1.4); }
  .node text { font-size: 10.5px; fill: #94a3b8; pointer-events: none; }

  .node.device circle { fill: #2d1f4e; stroke: #a78bfa; }
  .node.device .icon  { font-size: 14px; fill: #c4b5fd; }
  .node.vs circle     { fill: #1e3a5f; stroke: #3b82f6; }
  .node.vs .icon      { font-size: 11px; fill: #60a5fa; }

  /* iRule — base (status-attached fallback) */
  .node.irule circle  { fill: #12202e; stroke: #38bdf8; }
  .node.irule .icon   { font-size: 10px; fill: #7dd3fc; }

  /* Status overrides */
  .node.irule.status-active   circle { fill: #1a2e1a; stroke: #22c55e; }
  .node.irule.status-active   .icon  { fill: #4ade80; }
  .node.irule.status-orphan   circle { fill: #2e2a0a; stroke: #eab308; stroke-dasharray: 4 3; }
  .node.irule.status-orphan   .icon  { fill: #fbbf24; }
  .node.irule.status-error    circle { fill: #3d1212; stroke: #ef4444; }
  .node.irule.status-error    .icon  { fill: #f87171; }
  .node.irule.status-attached circle { fill: #12202e; stroke: #38bdf8; }
  .node.irule.status-attached .icon  { fill: #7dd3fc; }

  /* Duplicate — adds dash on top of status color (no fill override) */
  .node.irule.dup circle { stroke-dasharray: 4 2; }

  .node.selected circle { stroke-width: 3.5px; filter: brightness(1.55); }
  .node.dimmed circle   { opacity: 0.25; }
  .node.dimmed text     { opacity: 0.15; }
  .link.dimmed          { opacity: 0.08; }

  .legend { position: absolute; bottom: 16px; left: 16px; background: #1a1d2e; border: 1px solid #2d3148; border-radius: 8px; padding: 10px 14px; font-size: 0.72rem; line-height: 1.9; }
  .legend-row { display: flex; align-items: center; gap: 8px; }
  .ldot { width: 11px; height: 11px; border-radius: 50%; border: 2px solid; flex-shrink: 0; }
  .ldot.device           { background:#2d1f4e; border-color:#a78bfa; }
  .ldot.vs               { background:#1e3a5f; border-color:#3b82f6; }
  .ldot.irule-active     { background:#1a2e1a; border-color:#22c55e; }
  .ldot.irule-attached   { background:#12202e; border-color:#38bdf8; }
  .ldot.irule-orphan     { background:#2e2a0a; border-color:#eab308; border-style: dashed; }
  .ldot.irule-error      { background:#3d1212; border-color:#ef4444; }

  .hint { position: absolute; top: 14px; left: 50%; transform: translateX(-50%);
          font-size: 0.7rem; color: #334155; pointer-events: none; }
  .tooltip { position: absolute; background: #1a1d2e; border: 1px solid #3d4266; border-radius: 7px;
             padding: 9px 12px; font-size: 0.72rem; pointer-events: none; opacity: 0;
             transition: opacity 0.12s; max-width: 230px; word-break: break-word;
             z-index: 20; line-height: 1.65; }

  /* ── Code panel ── */
  #code-panel { width: 44%; min-width: 360px; max-width: 720px; display: flex; flex-direction: column; border-left: 1px solid #2d3148; background: #12151f; }

  /* header row */
  #code-header { padding: 8px 14px; background: #1a1d2e; border-bottom: 1px solid #2d3148; display: flex; align-items: center; gap: 8px; min-height: 42px; flex-shrink: 0; }
  #rule-name-display { font-size: 0.82rem; font-weight: 600; color: #22c55e; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  #copy-btn, #popout-btn { background: #1e3a5f; border: 1px solid #3b82f6; color: #93c5fd; border-radius: 4px; padding: 3px 10px; font-size: 0.7rem; cursor: pointer; display: none; flex-shrink: 0; }
  #copy-btn:hover, #popout-btn:hover { background: #254e7a; }
  #popout-btn { font-size: 0.85rem; padding: 2px 8px; }

  /* ── Floating popout panel ── */
  #popout-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.55); z-index: 100; }
  #popout-overlay.open { display: flex; align-items: center; justify-content: center; }
  #popout-window { background: #12151f; border: 1px solid #3d4266; border-radius: 10px; width: 72vw; height: 80vh; max-width: 1100px; display: flex; flex-direction: column; box-shadow: 0 24px 60px rgba(0,0,0,0.7); overflow: hidden; resize: both; }
  #popout-titlebar { padding: 9px 14px; background: #1a1d2e; border-bottom: 1px solid #2d3148; display: flex; align-items: center; gap: 8px; flex-shrink: 0; cursor: move; user-select: none; }
  #popout-title { font-size: 0.82rem; font-weight: 600; color: #22c55e; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  #popout-close { background: none; border: none; color: #4b5563; font-size: 1.1rem; cursor: pointer; padding: 0 4px; line-height: 1; }
  #popout-close:hover { color: #f87171; }
  #popout-body { display: flex; flex-direction: column; flex: 1; overflow: hidden; }
  #popout-source { flex: 1; overflow: auto; padding: 14px 18px; }
  #popout-code { font-family: 'JetBrains Mono','Fira Code',Consolas,monospace; font-size: 0.78rem; line-height: 1.65; white-space: pre; color: #a3e6b0; tab-size: 4; margin: 0; }
  #popout-ai-divider { background: #161926; border-top: 2px solid #2d3148; padding: 5px 14px; font-size: 0.68rem; font-weight: 600; color: #4b5563; text-transform: uppercase; letter-spacing: 0.06em; cursor: row-resize; user-select: none; flex-shrink: 0; display: flex; align-items: center; gap: 6px; }
  #popout-ai-divider:hover { color: #94a3b8; background: #1a1d2e; }
  #popout-ai-pane { flex: 0 0 200px; overflow: auto; padding: 12px 16px; background: #0d1117; }
  #popout-ai-pane.collapsed { display: none !important; }

  /* source pane — upper half */
  #source-pane { flex: 1; overflow: auto; padding: 14px 18px; min-height: 80px; }
  pre#code-view { font-family: 'JetBrains Mono','Fira Code',Consolas,monospace; font-size: 0.76rem; line-height: 1.65; white-space: pre; color: #a3e6b0; tab-size: 4; display: none; }

  .placeholder { display: flex; align-items: center; justify-content: center; height: 100%; color: #334155; font-size: 0.83rem; text-align: center; padding: 32px; }

  /* stats bar (between source and AI) */
  #stats { padding: 6px 14px; background: #1a1d2e; border-top: 1px solid #2d3148; font-size: 0.7rem; display: none; gap: 18px; flex-shrink: 0; }
  #stats span { color: #64748b; }
  #stats b { color: #94a3b8; }

  /* duplicate-info bar */
  #dup-info { display: none; padding: 5px 14px; background: #1c1710; border-top: 1px solid #78350f; font-size: 0.7rem; flex-shrink: 0; gap: 8px; flex-wrap: wrap; align-items: baseline; }
  .dup-badge { color: #fbbf24; font-weight: 700; margin-right: 6px; white-space: nowrap; }
  .dup-link  { color: #60a5fa; cursor: pointer; text-decoration: underline; white-space: nowrap; margin-right: 8px; }
  .dup-link:hover { color: #93c5fd; }
  .dup-hash  { color: #374151; font-family: monospace; font-size: 0.62rem; margin-left: auto; user-select: all; cursor: text; }

  /* XC library status bar */
  #xc-library-info { display: none; padding: 5px 14px; background: #0a1929; border-top: 1px solid #1e3a5f; font-size: 0.7rem; flex-shrink: 0; gap: 10px; align-items: center; flex-wrap: wrap; }
  .xc-lib-badge { display: inline-flex; align-items: center; gap: 5px; background: #0d2240; border: 1px solid #3b82f6; color: #60a5fa; border-radius: 3px; padding: 1px 8px; font-size: 0.65rem; font-weight: 700; white-space: nowrap; }
  .xc-lib-name  { color: #93c5fd; font-family: 'JetBrains Mono',Consolas,monospace; font-size: 0.68rem; }
  .xc-lib-when  { color: #334155; font-size: 0.65rem; margin-left: auto; }

  /* AI analysis pane — lower corner */
  #ai-divider { display: none; background: #161926; border-top: 2px solid #2d3148; padding: 5px 14px; font-size: 0.68rem; font-weight: 600; color: #4b5563; text-transform: uppercase; letter-spacing: 0.06em; cursor: row-resize; user-select: none; flex-shrink: 0; display: flex; align-items: center; gap: 6px; }
  #ai-divider:hover { color: #94a3b8; background: #1a1d2e; }
  #ai-divider .ai-chevron { transition: transform 0.2s; font-style: normal; }
  #ai-divider.collapsed .ai-chevron { transform: rotate(-90deg); }
  #ai-pane { flex: 0 0 220px; overflow: auto; padding: 12px 16px; border-top: 1px solid #1a1d2e; background: #0d1117; display: none; }
  #ai-pane.collapsed { display: none !important; }
  .ai-label { font-size: 0.65rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 8px; }
  .ai-label.ok   { color: #4ade80; }
  .ai-label.fail { color: #f87171; }
  .ai-label.none { color: #4b5563; }
  #ai-text { font-family: 'Segoe UI', system-ui, sans-serif; font-size: 0.78rem; line-height: 1.75; color: #94a3b8; }
  #ai-text p, .ai-body p  { margin: 4px 0 8px; }
  #ai-text ol, #ai-text ul,
  .ai-body  ol, .ai-body  ul { padding-left: 20px; margin: 4px 0 8px; }
  #ai-text li, .ai-body li  { margin: 3px 0; }
  #ai-text strong, #ai-text b,
  .ai-body  strong, .ai-body b { color: #c4b5fd; }
  #ai-text em, #ai-text i,
  .ai-body  em, .ai-body  i  { color: #93c5fd; font-style: italic; }
  #ai-text code, .ai-body code { background: #1a2e1a; padding: 1px 5px; border-radius: 3px; font-family: 'JetBrains Mono',Consolas,monospace; font-size: 0.72rem; color: #4ade80; }
  #ai-text pre, .ai-body pre  { background: #1a2e1a; border: 1px solid #2d4a2d; border-radius: 5px; padding: 8px 10px; overflow-x: auto; margin: 6px 0; }
  #ai-text pre code, .ai-body pre code { background: none; padding: 0; color: #86efac; }
  #ai-text h1,#ai-text h2,#ai-text h3,#ai-text h4,#ai-text h5,#ai-text h6,
  .ai-body  h1,.ai-body  h2,.ai-body  h3,.ai-body  h4,.ai-body  h5,.ai-body  h6 { color: #a78bfa; margin: 12px 0 4px; font-weight: 700; }
  #ai-text h4, .ai-body h4 { font-size: 0.85rem; }
  #ai-text h5, .ai-body h5 { font-size: 0.80rem; color: #c4b5fd; }
  #ai-text h6, .ai-body h6 { font-size: 0.76rem; color: #c4b5fd; }
  #ai-text a, .ai-body a   { color: #60a5fa; text-decoration: none; }
  #ai-text a:hover, .ai-body a:hover { text-decoration: underline; }
  #ai-text hr, .ai-body hr { border: none; border-top: 1px solid #2d3148; margin: 10px 0; }

  /* ── Fleet view ── */
  #pane-fleet { flex: 1; display: none; flex-direction: column; overflow: hidden; background: #080c12; }
  #pane-fleet.active { display: flex; }
  #fleet-toolbar { display: flex; align-items: center; gap: 10px; padding: 8px 14px; background: #0d1117; border-bottom: 1px solid #1e2638; flex-shrink: 0; flex-wrap: wrap; }
  #fleet-search { background: #161926; border: 1px solid #2d3148; border-radius: 6px; color: #94a3b8; font-size: 0.78rem; padding: 5px 10px; width: 210px; outline: none; }
  #fleet-search:focus { border-color: #a78bfa; }
  #fleet-status-filters, #fleet-sort-btns { display: flex; gap: 4px; align-items: center; }
  .fleet-sort-label { font-size: 0.68rem; color: #4b5563; text-transform: uppercase; letter-spacing: 0.05em; }
  .flt-btn, .fsort-btn { background: #161926; border: 1px solid #2d3148; border-radius: 5px; color: #4b5563; font-size: 0.72rem; font-weight: 600; padding: 4px 10px; cursor: pointer; letter-spacing: 0.03em; transition: color 0.12s, border-color 0.12s, background 0.12s; }
  .flt-btn:hover, .fsort-btn:hover { color: #94a3b8; border-color: #4b5563; }
  .flt-btn.active, .fsort-btn.active { color: #c4b5fd; border-color: #a78bfa; background: #1a1430; }
  .flt-btn.error  { color: #f87171; border-color: #7f1d1d; }
  .flt-btn.error.active  { background: #2a0808; border-color: #ef4444; }
  .flt-btn.orphan { color: #fbbf24; border-color: #78350f; }
  .flt-btn.orphan.active { background: #1e1505; border-color: #eab308; }
  .flt-btn.active2 { color: #4ade80; border-color: #14532d; }
  .flt-btn.active2.active { background: #071a0e; border-color: #22c55e; }
  .flt-btn.attch  { color: #38bdf8; border-color: #0c4a6e; }
  .flt-btn.attch.active  { background: #051218; border-color: #38bdf8; }
  #fleet-counts { margin-left: auto; font-size: 0.70rem; color: #4b5563; white-space: nowrap; }
  #fleet-grid { flex: 1; overflow-y: auto; padding: 12px 14px; display: grid; grid-template-columns: repeat(auto-fill, minmax(168px, 1fr)); gap: 6px; align-content: start; }
  .fleet-tile { background: #0d1117; border: 1px solid #1e2638; border-left: 4px solid #2d3148; border-radius: 6px; padding: 8px 10px; cursor: pointer; transition: filter 0.12s, border-color 0.12s; display: flex; flex-direction: column; gap: 4px; min-width: 0; }
  .fleet-tile:hover { filter: brightness(1.35); border-color: #4b5563; }
  .fleet-tile.st-error    { border-left-color: #ef4444; background: #100808; }
  .fleet-tile.st-orphan   { border-left-color: #eab308; background: #0e0c04; }
  .fleet-tile.st-active   { border-left-color: #22c55e; background: #071008; }
  .fleet-tile.st-attached { border-left-color: #38bdf8; background: #050e14; }
  .fleet-tile.st-unreachable { border-left-color: #6b7280; background: #0d0d0d; }
  .ft-host { font-family: 'JetBrains Mono', Consolas, monospace; font-size: 0.70rem; color: #c4b5fd; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; font-weight: 600; }
  .ft-meta { font-size: 0.65rem; color: #4b5563; white-space: nowrap; }
  .ft-dots { display: flex; gap: 4px; align-items: center; flex-wrap: wrap; margin-top: 1px; }
  .ft-dot  { display: inline-flex; align-items: center; gap: 2px; font-size: 0.62rem; font-weight: 700; border-radius: 3px; padding: 1px 5px; }
  .ft-dot.err  { background: rgba(239,68,68,0.18);  color: #fca5a5; }
  .ft-dot.orp  { background: rgba(234,179,8,0.18);  color: #fde68a; }
  .ft-dot.act  { background: rgba(34,197,94,0.18);  color: #86efac; }
  .ft-dot.att  { background: rgba(56,189,248,0.18); color: #7dd3fc; }
  .fleet-empty { grid-column: 1/-1; text-align: center; color: #4b5563; font-size: 0.85rem; padding: 60px 0; }

  /* ── ServiceNow trigger button ── */
  #snow-trigger-btn { display: none; background: #0c2a3e; border: 1px solid #0369a1; color: #38bdf8; border-radius: 4px; padding: 3px 10px; font-size: 0.70rem; font-weight: 700; cursor: pointer; flex-shrink: 0; gap: 4px; transition: background 0.15s; }
  #snow-trigger-btn:hover { background: #0f3a56; border-color: #38bdf8; }
  #snow-trigger-count { font-size: 0.68rem; }

  /* ── ServiceNow flyout ── */
  #snow-backdrop { position: fixed; inset: 0; background: rgba(0,0,0,0.45); z-index: 1100; display: none; }
  #snow-backdrop.open { display: block; }
  #snow-flyout { position: fixed; top: 0; right: 0; width: 420px; max-width: 90vw; height: 100vh; background: #0a0f1a; border-left: 2px solid #0369a1; z-index: 1101; display: flex; flex-direction: column; transform: translateX(100%); transition: transform 0.28s cubic-bezier(0.4,0,0.2,1); box-shadow: -8px 0 32px rgba(0,0,0,0.6); }
  #snow-flyout.open { transform: translateX(0); }
  #snow-flyout-header { padding: 14px 16px 10px; background: #0d1a2e; border-bottom: 1px solid #1e3048; flex-shrink: 0; }
  #snow-flyout-title { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
  #snow-flyout-icon { font-size: 1rem; color: #38bdf8; font-style: normal; }
  #snow-flyout-title > span:nth-child(2) { font-size: 0.80rem; font-weight: 700; color: #7dd3fc; text-transform: uppercase; letter-spacing: 0.06em; }
  #snow-flyout-badge { background: #0c4a6e; color: #38bdf8; font-size: 0.60rem; font-weight: 700; border-radius: 10px; padding: 1px 8px; }
  #snow-flyout-irule { font-family: 'JetBrains Mono',Consolas,monospace; font-size: 0.68rem; color: #4b5563; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  #snow-flyout-close { position: absolute; top: 12px; right: 14px; background: none; border: none; color: #4b5563; font-size: 1rem; cursor: pointer; padding: 2px 6px; border-radius: 3px; }
  #snow-flyout-close:hover { color: #94a3b8; background: #1e2638; }
  #snow-flyout-body { flex: 1; overflow-y: auto; padding: 14px 16px; }
  .snow-ticket { border-left: 3px solid #0369a1; background: #060e18; border-radius: 5px; padding: 10px 12px; margin-bottom: 10px; }
  .snow-ticket:last-child { margin-bottom: 0; }
  .snow-ticket-header { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; flex-wrap: wrap; }
  .snow-num { font-family: 'JetBrains Mono',Consolas,monospace; font-size: 0.78rem; font-weight: 700; color: #38bdf8; text-decoration: none; }
  .snow-num:hover { text-decoration: underline; color: #7dd3fc; }
  .snow-type-badge { font-size: 0.60rem; font-weight: 700; border-radius: 3px; padding: 2px 6px; text-transform: uppercase; }
  .snow-summary { font-size: 0.75rem; color: #94a3b8; line-height: 1.6; margin-bottom: 6px; }
  .snow-ctx { font-family: 'JetBrains Mono',Consolas,monospace; font-size: 0.65rem; color: #4b5563; background: #0d1117; border: 1px solid #1e2638; border-radius: 4px; padding: 6px 8px; overflow-x: auto; white-space: pre; line-height: 1.5; }
  .snow-empty { color: #4b5563; font-size: 0.80rem; text-align: center; padding: 40px 0; }

  /* ── Tab bar ── */
  .tab-bar { display: flex; background: #161926; border-bottom: 1px solid #2d3148; padding: 0 16px; flex-shrink: 0; gap: 2px; }
  .tab-btn { background: none; border: none; border-bottom: 2px solid transparent; color: #4b5563; font-size: 0.78rem; font-weight: 600; padding: 8px 18px; cursor: pointer; letter-spacing: 0.03em; transition: color 0.15s; margin-bottom: -1px; white-space: nowrap; }
  .tab-btn:hover { color: #94a3b8; }
  .tab-btn.active { color: #a78bfa; border-bottom-color: #a78bfa; }

  /* ── Sankey pane ── */
  #pane-sankey { flex: 1; display: none; overflow: hidden; background: #0f1117; position: relative; }
  #pane-sankey.active { display: flex; }
  #sankey-svg  { width: 100%; height: 100%; }
  .sk-tooltip  { position: fixed; background: #1e2235; border: 1px solid #3d4266; border-radius: 6px;
                 padding: 7px 11px; font-size: 0.72rem; pointer-events: none; opacity: 0;
                 transition: opacity 0.12s; z-index: 50; max-width: 320px; color: #e2e8f0; line-height: 1.55; }
</style>
</head>
<body>

<header>
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#a78bfa" stroke-width="2">
    <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>
    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
  </svg>
  <h1>BIG-IP iRule Discovery</h1>
  <div id="summary"></div>
</header>

<div class="tab-bar">
  <button class="tab-btn active" id="tab-fleet"  onclick="switchTab('fleet')">&#9783; Device Fleet</button>
  <button class="tab-btn"        id="tab-force"  onclick="switchTab('force')">&#11042; Force Graph</button>
  <button class="tab-btn"        id="tab-sankey" onclick="switchTab('sankey')">&#8644; Sankey Flow</button>
</div>

<div class="main-area">
  <div class="diagram-area">
    <div id="pane-force">
      <div id="graph-panel">
        <svg id="svg"></svg>
        <div class="hint">Scroll to zoom · Drag to pan · Click iRule to view source</div>
        <div class="legend">
          <div class="legend-row"><div class="ldot device"></div>BIG-IP Device</div>
          <div class="legend-row"><div class="ldot vs"></div>Virtual Server</div>
          <div class="legend-row"><div class="ldot irule-active"></div>iRule — active</div>
          <div class="legend-row"><div class="ldot irule-attached"></div>iRule — no executions</div>
          <div class="legend-row"><div class="ldot irule-orphan"></div>iRule — orphaned</div>
          <div class="legend-row"><div class="ldot irule-error"></div>iRule — errors/aborts</div>
        </div>
        <div class="tooltip" id="tooltip"></div>
      </div>
    </div>

    <div id="pane-sankey">
      <svg id="sankey-svg"></svg>
      <div class="sk-tooltip" id="sk-tooltip"></div>
    </div>

    <div id="pane-fleet">
      <div id="fleet-toolbar">
        <input id="fleet-search" type="search" placeholder="&#128269; Filter devices…" autocomplete="off">
        <div id="fleet-status-filters">
          <button class="flt-btn active" data-s="all">All</button>
          <button class="flt-btn error"   data-s="error">Error</button>
          <button class="flt-btn orphan"  data-s="orphan">Orphan</button>
          <button class="flt-btn active2" data-s="active">Active</button>
          <button class="flt-btn attch"   data-s="attached">Attached</button>
        </div>
        <div id="fleet-sort-btns">
          <span class="fleet-sort-label">Sort:</span>
          <button class="fsort-btn active" data-sort="status">Severity</button>
          <button class="fsort-btn" data-sort="name">Name</button>
          <button class="fsort-btn" data-sort="rules">Rules ↓</button>
        </div>
        <div id="fleet-counts"></div>
      </div>
      <div id="fleet-grid"></div>
    </div>
  </div>

  <div class="resize-v" id="resize-v"></div>

  <div id="code-panel">
    <div id="code-header">
      <div id="rule-name-display">Select an iRule to view source</div>
      <button id="popout-btn" onclick="popoutPanel()" title="Open in floating window">&#x2922;</button>
      <button id="copy-btn" onclick="copyCode()">Copy</button>
      <button id="snow-trigger-btn" onclick="openSNowFlyout()" title="View ServiceNow ticket references">&#10052; <span id="snow-trigger-count"></span></button>
    </div>
    <div id="source-pane">
      <div class="placeholder" id="placeholder">Click any iRule node in the diagram to view its source and AI analysis.</div>
      <pre id="code-view"></pre>
    </div>
    <div id="stats">
      <span>Lines: <b id="stat-lines"></b></span>
      <span>Chars: <b id="stat-chars"></b></span>
      <span>Device: <b id="stat-host"></b></span>
      <span id="stat-exec-wrap" style="display:none">
        Exec: <b id="stat-exec"></b><span id="stat-errs"></span>
      </span>
    </div>
    <div id="dup-info"></div>
    <div id="xc-library-info"></div>
    <div id="ai-divider">
      <em class="ai-chevron">▾</em>
      <span>AI Analysis</span>
      <span id="ai-badge"></span>
    </div>
    <div id="ai-pane">
      <div class="ai-label none" id="ai-label">No analysis available</div>
      <div id="ai-text"></div>
    </div>
  </div>
</div>

<!-- ServiceNow flyout backdrop + panel -->
<div id="snow-backdrop" onclick="closeSNowFlyout()"></div>
<div id="snow-flyout">
  <div id="snow-flyout-header">
    <div id="snow-flyout-title">
      <span id="snow-flyout-icon">&#10052;</span>
      <span>ServiceNow References</span>
      <span id="snow-flyout-badge"></span>
    </div>
    <div id="snow-flyout-irule"></div>
    <button id="snow-flyout-close" onclick="closeSNowFlyout()" title="Close">&#10005;</button>
  </div>
  <div id="snow-flyout-body"></div>
</div>

<div id="popout-overlay" onclick="if(event.target===this)closePopout()">
  <div id="popout-window">
    <div id="popout-titlebar">
      <span id="popout-title">iRule</span>
      <button id="popout-close" onclick="closePopout()">&#x2715;</button>
    </div>
    <div id="popout-body">
      <div id="popout-source"><pre id="popout-code"></pre></div>
      <div id="popout-ai-divider">
        <em class="ai-chevron" id="popout-chevron">&#9662;</em>
        <span>AI Analysis</span>
      </div>
      <div id="popout-ai-pane">
        <div class="ai-label none" id="popout-ai-label">No analysis available</div>
        <div id="popout-ai-text"></div>
      </div>
    </div>
  </div>
</div>

<script>
const DATA = __DATA__;

// ── Helpers ──────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function statusColor(s) {
  return s==='error'?'#ef4444':s==='orphan'?'#eab308':s==='active'?'#4ade80':'#38bdf8';
}

function sparkline(history, w=160, h=42) {
  if (!history || history.length < 2) return '';
  // Use delta_executions (rate per interval) if present, else fall back to cumulative
  const vals   = history.map(h => h.delta_executions !== undefined ? h.delta_executions : h.total_executions);
  const allZero = vals.every(v => v === 0);
  if (allZero) return '<div style="color:#374151;font-size:0.65rem;margin-top:4px">no executions recorded</div>';
  const mx     = Math.max(...vals, 1);
  const hasErr = history.some(h => h.failures > 0 || h.aborts > 0);
  const lc     = hasErr ? '#f87171' : '#4ade80';
  const ac     = hasErr ? 'rgba(248,113,113,0.12)' : 'rgba(74,222,128,0.12)';
  const TPAD   = 10;  // top padding for label
  const BPAD   = 12;  // bottom padding for date labels
  const plotH  = h - TPAD - BPAD;
  const pts    = vals.map((v,i)=>{
    const x = (2 + (i/(vals.length-1))*(w-4)).toFixed(1);
    const y = (TPAD + plotH - (v/mx)*plotH).toFixed(1);
    return `${x},${y}`;
  });
  const last   = pts[pts.length-1].split(',');
  const area   = `2,${TPAD+plotH} ${pts.join(' ')} ${last[0]},${TPAD+plotH}`;
  const d0     = history[0].run_at.slice(0,10);
  const dN     = history[history.length-1].run_at.slice(0,10);
  const peak   = Math.max(...vals);
  return `<svg width="${w}" height="${h}" style="display:block;margin-top:5px">
    <text x="${w-1}" y="8" font-size="7.5" fill="#475569" text-anchor="end">peak ${peak.toLocaleString()}/interval</text>
    <polygon points="${area}" fill="${ac}"/>
    <polyline points="${pts.join(' ')}" fill="none" stroke="${lc}" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>
    <text x="1" y="${h-1}" font-size="7.5" fill="#374151">${d0}</text>
    <text x="${w-1}" y="${h-1}" font-size="7.5" fill="#374151" text-anchor="end">${dN}</text>
  </svg>`;
}

// ── Summary bar ─────────────────────────────────────────────────────────────
const devicesOk   = DATA.devices.filter(d => !d.error).length;
const totalVS     = DATA.devices.reduce((n, d) => n + d.virtual_servers.length, 0);
const vsWithRules = DATA.devices.reduce((n, d) =>
  n + d.virtual_servers.filter(vs => vs.rule_keys && vs.rule_keys.length > 0).length, 0);
const totalRules  = Object.keys(DATA.irules).length;
const aiAnalysed  = Object.values(DATA.irules).filter(r => r.ai_analysis && r.ai_analysis.status === 'success').length;
const dupCount    = Object.values(DATA.irules).filter(r => r.duplicate_keys && r.duplicate_keys.length > 0).length;
const orphanCount = Object.values(DATA.irules).filter(r => r.irule_status === 'orphan').length;
const errorCount  = Object.values(DATA.irules).filter(r => r.irule_status === 'error').length;

function pill(val, label, accent) {
  return `<div class="stat-pill"><span class="stat-val ${accent}">${val}</span><span class="stat-lbl">${label}</span></div>`;
}
let summaryHTML =
  pill(devicesOk,              'Devices',         'accent-purple') +
  pill(totalVS,                'Virtual Servers', 'accent-blue')   +
  pill(vsWithRules,            'VS with iRules',  'accent-green')  +
  pill(totalVS - vsWithRules,  'VS no iRules',    'accent-amber')  +
  pill(totalRules,             'iRules',          'accent-green');
if (errorCount  > 0) summaryHTML += pill(errorCount,  'Errors',      'accent-red'   );
if (orphanCount > 0) summaryHTML += pill(orphanCount, 'Orphaned',    'accent-amber' );
if (dupCount    > 0) summaryHTML += pill(dupCount,    'Duplicates',  'accent-amber' );
if (aiAnalysed  > 0) summaryHTML += pill(aiAnalysed,  'AI Analysed', 'accent-purple');
document.getElementById('summary').innerHTML = summaryHTML;

// ── Build graph nodes / links ───────────────────────────────────────────────
const nodes = [], links = [];
const vsSet = {}, ruleSet = {};

function makeIRuleNode(rk, devHost) {
  const rd = DATA.irules[rk];
  return {
    id: rk, type: 'irule', tier: 2,
    label:          rd ? rd.path.replace(/^.*\//, '') : rk,
    full:           rd ? rd.path : rk,
    host:           rd ? rd.host : devHost,
    code:           rd ? rd.code : '# source not available',
    ai_analysis:    rd ? rd.ai_analysis   : null,
    content_hash:   rd ? rd.content_hash  : null,
    duplicate_keys: rd ? (rd.duplicate_keys  || []) : [],
    xc_library:     rd ? (rd.xc_library   || null) : null,
    irule_status:        rd ? (rd.irule_status        || 'attached') : 'attached',
    stats:               rd ? (rd.stats               || null) : null,
    stats_history:       rd ? (rd.stats_history       || []) : [],
    servicenow_tickets:  rd ? (rd.servicenow_tickets  || []) : [],
  };
}

DATA.devices.forEach(dev => {
  const devId = `dev::${dev.host}`;
  nodes.push({ id: devId, label: dev.host, type: 'device', full: dev.host, tier: 0 });

  (dev.virtual_servers || []).forEach(vs => {
    const vsId = `vs::${dev.host}::${vs.full_path}`;
    if (!vsSet[vsId]) {
      vsSet[vsId] = true;
      nodes.push({ id: vsId, label: vs.name, type: 'vs', full: vs.full_path, tier: 1 });
    }
    links.push({ source: devId, target: vsId, linkType: 'dev-vs' });

    (vs.rule_keys || []).forEach(rk => {
      if (!ruleSet[rk]) {
        ruleSet[rk] = true;
        nodes.push(makeIRuleNode(rk, dev.host));
      }
      links.push({ source: vsId, target: rk, linkType: 'vs-rule' });
    });
  });
});

// Add orphan iRules (not attached to any VS) as floating nodes
Object.entries(DATA.irules).forEach(([rk, rd]) => {
  if (!ruleSet[rk] && rd.irule_status === 'orphan') {
    ruleSet[rk] = true;
    nodes.push(makeIRuleNode(rk, rd.host));
  }
});

// ── D3 force simulation ─────────────────────────────────────────────────────
const panel   = document.getElementById('graph-panel');
const tooltip = document.getElementById('tooltip');
let W = panel.clientWidth, H = panel.clientHeight;

const svg = d3.select('#svg');
const g   = svg.append('g');
const zoomBehavior = d3.zoom().scaleExtent([0.1, 5]).on('zoom', e => g.attr('transform', e.transform));
svg.call(zoomBehavior);

const sim = d3.forceSimulation(nodes)
  .force('link', d3.forceLink(links).id(d => d.id)
    .distance(l => l.linkType === 'dev-vs' ? 160 : 100)
    .strength(l => l.linkType === 'dev-vs' ? 0.7 : 0.5))
  .force('charge', d3.forceManyBody()
    .strength(d => d.type === 'device' ? -800 : d.type === 'vs' ? -350 : -180))
  .force('center', d3.forceCenter(W / 2, H / 2))
  .force('collision', d3.forceCollide(d => d.type === 'device' ? 50 : d.type === 'vs' ? 34 : 24))
  .force('tier', d3.forceY(d => (d.tier / 2) * H * 0.6 + H * 0.2).strength(0.08));

const linkSel = g.append('g').selectAll('line')
  .data(links).join('line')
  .attr('class', l => `link ${l.linkType}`);

const nodeSel = g.append('g').selectAll('g')
  .data(nodes).join('g')
  .attr('class', d => {
    let cls = `node ${d.type}`;
    if (d.type === 'irule') cls += ` status-${d.irule_status || 'attached'}`;
    if (d.duplicate_keys && d.duplicate_keys.length) cls += ' dup';
    return cls;
  })
  .call(d3.drag()
    .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
    .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y; })
    .on('end',   (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; }));

const radii = { device: 28, vs: 20, irule: 14 };

nodeSel.append('circle')
  .attr('r', d => radii[d.type])
  .on('click', (e, d) => { e.stopPropagation(); if (d.type === 'irule') showCode(d); selectNode(d); })
  .on('mouseover', (e, d) => {
    if (d.type === 'irule') {
      const sc  = statusColor(d.irule_status || 'attached');
      const sta = (d.irule_status || 'attached').toUpperCase();
      let html  = `<div style="color:${sc};font-weight:600;margin-bottom:2px">${escHtml(d.full)}</div>`;
      html += `<div style="color:#64748b;font-size:0.65rem;margin-bottom:4px">${sta}`;
      if (d.duplicate_keys && d.duplicate_keys.length) html += ' · duplicate';
      html += '</div>';
      const s = d.stats;
      if (s) {
        const lastDelta = d.stats_history && d.stats_history.length > 0
          ? d.stats_history[d.stats_history.length-1].delta_executions : undefined;
        html += `<div style="font-size:0.7rem;color:#94a3b8">`;
        html += `Total: <b style="color:#e2e8f0">${s.total_executions.toLocaleString()}</b>`;
        if (lastDelta !== undefined) html += ` <span style="color:#64748b">· last: ${lastDelta.toLocaleString()}/interval</span>`;
        if (s.failures) html += ` <span style="color:#f87171">· Fail: ${s.failures}</span>`;
        if (s.aborts)   html += ` <span style="color:#fb923c">· Abort: ${s.aborts}</span>`;
        html += '</div>';
      }
      html += sparkline(d.stats_history);
      tooltip.innerHTML = html;
    } else {
      tooltip.textContent = d.full;
    }
    tooltip.style.opacity = 1;
  })
  .on('mousemove', e => { tooltip.style.left = (e.offsetX + 16) + 'px'; tooltip.style.top = (e.offsetY - 8) + 'px'; })
  .on('mouseout',  () => { tooltip.style.opacity = 0; });

nodeSel.append('text').attr('class', 'icon').attr('text-anchor', 'middle').attr('dy', '0.35em')
  .text(d => d.type === 'device' ? '⬡' : d.type === 'vs' ? 'VS' : 'iR');

nodeSel.append('text').attr('text-anchor', 'middle')
  .attr('dy', d => radii[d.type] + 13)
  .text(d => d.label.length > 22 ? d.label.slice(0, 20) + '…' : d.label);

sim.on('tick', () => {
  linkSel.attr('x1', l => l.source.x).attr('y1', l => l.source.y)
         .attr('x2', l => l.target.x).attr('y2', l => l.target.y);
  nodeSel.attr('transform', d => `translate(${d.x},${d.y})`);
});

svg.on('click', () => clearSelection());

// ── Selection / dimming ─────────────────────────────────────────────────────
let selectedId = null;

function selectNode(d) {
  if (selectedId === d.id) { clearSelection(); return; }
  selectedId = d.id;
  const conn = new Set([d.id]);
  links.forEach(l => {
    if (l.source.id === d.id) conn.add(l.target.id);
    if (l.target.id === d.id) conn.add(l.source.id);
  });
  if (d.type === 'device') {
    const vsIds = new Set();
    links.forEach(l => { if (l.source.id === d.id) vsIds.add(l.target.id); });
    links.forEach(l => { if (vsIds.has(l.source.id)) conn.add(l.target.id); });
  }
  nodeSel.classed('selected', n => n.id === d.id).classed('dimmed', n => !conn.has(n.id));
  linkSel.classed('highlighted', l => l.source.id === d.id || l.target.id === d.id)
         .classed('dimmed', l => !conn.has(l.source.id) || !conn.has(l.target.id));
}

function clearSelection() {
  selectedId = null;
  nodeSel.classed('selected', false).classed('dimmed', false);
  linkSel.classed('highlighted', false).classed('dimmed', false);
  document.getElementById('placeholder').style.display = 'flex';
  document.getElementById('code-view').style.display = 'none';
  document.getElementById('stats').style.display = 'none';
  document.getElementById('dup-info').style.display = 'none';
  document.getElementById('xc-library-info').style.display = 'none';
  document.getElementById('copy-btn').style.display = 'none';
  document.getElementById('popout-btn').style.display = 'none';
  document.getElementById('ai-divider').style.display = 'none';
  document.getElementById('ai-pane').style.display = 'none';
  document.getElementById('snow-trigger-btn').style.display = 'none';
  document.getElementById('rule-name-display').textContent = 'Select an iRule to view source';
}

// ── AI pane toggle ──────────────────────────────────────────────────────────
let aiCollapsed = false;
function toggleAI() {
  aiCollapsed = !aiCollapsed;
  document.getElementById('ai-divider').classList.toggle('collapsed', aiCollapsed);
  document.getElementById('ai-pane').classList.toggle('collapsed', aiCollapsed);
}

// ── BIG-IP escape decoder ────────────────────────────────────────────────────
// BIG-IP's apiAnonymous field uses JSON-style escape sequences (\n \t \")
// instead of actual characters.  Decode them so source displays correctly.
function decodeBigIP(s) {
  return s
    .replace(/\\\\/g, '\x00')   // protect literal backslash
    .replace(/\\n/g,  '\n')
    .replace(/\\t/g,  '\t')
    .replace(/\\r/g,  '\r')
    .replace(/\\"/g,  '"')
    .replace(/\x00/g, '\\');    // restore literal backslash
}

// ── AI text renderer ────────────────────────────────────────────────────────
// Converts Markdown (as returned by Claude / OpenAI) to readable HTML.
// Handles: headings, bold, italic, inline code, fenced code blocks,
//          bullet lists (nested via indent), horizontal rules, paragraphs.
function renderAI(text) {
  if (!text) return '';
  // Strip any script tags before inserting as innerHTML
  text = text.replace(/<script[\s\S]*?<\/script>/gi, '');
  // If the response is already HTML, render it directly
  if (/<[a-zA-Z][\s\S]*?>/.test(text)) return text;

  // ── pass 1: extract fenced code blocks to avoid mangling their contents ──
  const blocks = [];
  text = text.replace(/```(\w*)\n?([\s\S]*?)```/g, (_, lang, code) => {
    const idx = blocks.length;
    const escaped = code.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const cls = lang ? ` class="language-${lang}"` : '';
    blocks.push(`<pre><code${cls}>${escaped}</code></pre>`);
    return `\x00BLOCK${idx}\x00`;
  });

  // ── pass 2: escape remaining HTML ──
  text = text.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  // ── pass 3: line-by-line processing ──
  const lines = text.split('\n');
  const out   = [];
  let   inUL  = false;   // inside a <ul>

  const flushList = () => { if (inUL) { out.push('</ul>'); inUL = false; } };

  const inlineFormat = s =>
    s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
     .replace(/\*(.+?)\*/g,     '<em>$1</em>')
     .replace(/`([^`]+)`/g,     '<code>$1</code>');

  for (let i = 0; i < lines.length; i++) {
    const raw  = lines[i];
    const line = raw.trimEnd();

    // fenced code block placeholder
    if (/^\x00BLOCK\d+\x00$/.test(line.trim())) {
      flushList();
      out.push(line.trim());
      continue;
    }

    // horizontal rule
    if (/^---+$/.test(line.trim())) {
      flushList();
      out.push('<hr>');
      continue;
    }

    // headings  ## 1. Objective  /  ### Sub  etc.
    const hm = line.match(/^(#{1,6})\s+(.*)/);
    if (hm) {
      flushList();
      const lvl  = Math.min(hm[1].length + 2, 6);   // ## → h4, ### → h5, etc.
      out.push(`<h${lvl}>${inlineFormat(hm[2])}</h${lvl}>`);
      continue;
    }

    // bullet list item  (- or • or *)
    const lm = line.match(/^(\s*)[-•*]\s+(.*)/);
    if (lm) {
      if (!inUL) { out.push('<ul>'); inUL = true; }
      out.push(`<li>${inlineFormat(lm[2])}</li>`);
      continue;
    }

    // numbered list item
    const nm = line.match(/^(\s*)\d+[.)]\s+(.*)/);
    if (nm) {
      if (!inUL) { out.push('<ul>'); inUL = true; }
      out.push(`<li>${inlineFormat(nm[2])}</li>`);
      continue;
    }

    // blank line → paragraph break
    if (line.trim() === '') {
      flushList();
      out.push('<p>');
      continue;
    }

    // plain paragraph text
    flushList();
    out.push(inlineFormat(line) + ' ');
  }
  flushList();

  // ── pass 4: restore fenced code blocks ──
  let html = out.join('\n');
  blocks.forEach((b, idx) => { html = html.replace(`\x00BLOCK${idx}\x00`, b); });

  // collapse runs of empty <p> tags
  html = html.replace(/(<p>\s*){2,}/g, '<p>');

  return `<div class="ai-body">${html}</div>`;
}

// ── Code viewer ─────────────────────────────────────────────────────────────
let currentCode = '';
let currentAI   = null;

function showCode(d) {
  currentCode = decodeBigIP(d.code || '# no source available');
  currentAI   = d.ai_analysis || null;

  document.getElementById('rule-name-display').textContent = d.full;

  // Source
  document.getElementById('code-view').textContent = currentCode;
  document.getElementById('placeholder').style.display = 'none';
  document.getElementById('code-view').style.display = 'block';
  document.getElementById('copy-btn').style.display = 'block';
  document.getElementById('popout-btn').style.display = 'block';

  // Stats
  const statsEl = document.getElementById('stats');
  statsEl.style.display = 'flex';
  document.getElementById('stat-lines').textContent = currentCode.split('\n').length;
  document.getElementById('stat-chars').textContent = currentCode.length;
  document.getElementById('stat-host').textContent  = d.host || '';
  const execWrap = document.getElementById('stat-exec-wrap');
  const s = d.stats;
  if (s && (s.total_executions > 0 || s.failures > 0 || s.aborts > 0)) {
    document.getElementById('stat-exec').textContent = s.total_executions.toLocaleString();
    const errsEl = document.getElementById('stat-errs');
    errsEl.innerHTML = (s.failures ? `<span style="color:#f87171"> · Fail: ${s.failures}</span>` : '') +
                       (s.aborts   ? `<span style="color:#fb923c"> · Abort: ${s.aborts}</span>`  : '');
    execWrap.style.display = 'inline';
  } else {
    execWrap.style.display = 'none';
  }

  // XC Library status bar
  const xcLibEl = document.getElementById('xc-library-info');
  const xcLib   = d.xc_library;
  if (xcLib && xcLib.xc_name) {
    const when = xcLib.uploaded_at ? new Date(xcLib.uploaded_at).toLocaleString() : '';
    xcLibEl.innerHTML =
      '<span class="xc-lib-badge">\u2601 In XC Library</span>' +
      '<span class="xc-lib-name">' + xcLib.xc_name + '</span>' +
      (xcLib.xc_namespace ? '<span style="color:#334155">' + xcLib.xc_namespace + '</span>' : '') +
      (when ? '<span class="xc-lib-when">uploaded ' + when + '</span>' : '');
    xcLibEl.style.display = 'flex';
  } else {
    xcLibEl.style.display = 'none';
  }

  // Duplicate info bar
  const dupEl   = document.getElementById('dup-info');
  const dupKeys = d.duplicate_keys || [];
  if (dupKeys.length > 0) {
    const shortHash = (d.content_hash || '').slice(0, 12);
    const links = dupKeys.map(k => {
      const rd = DATA.irules[k];
      const label = rd ? rd.path + (rd.host !== d.host ? ' \u2022 ' + rd.host : '') : k;
      return `<span class="dup-link" onclick="jumpToDup('${k}')">${label}</span>`;
    }).join('');
    dupEl.innerHTML = `<span class="dup-badge">\u26a0 ${dupKeys.length} duplicate${dupKeys.length > 1 ? 's' : ''}</span>${links}<span class="dup-hash" title="Content SHA-256">${shortHash}\u2026</span>`;
    dupEl.style.display = 'flex';
  } else {
    dupEl.style.display = 'none';
  }

  // AI analysis — lower pane
  const ai = d.ai_analysis;
  const labelEl = document.getElementById('ai-label');
  const textEl  = document.getElementById('ai-text');
  const badgeEl = document.getElementById('ai-badge');

  if (ai && ai.status === 'success') {
    labelEl.className = 'ai-label ok';
    labelEl.textContent = ai.provider ? (ai.model ? `${ai.provider} / ${ai.model}` : ai.provider) : 'AI Assistant';
    textEl.innerHTML = renderAI(ai.analysis || '');
    badgeEl.textContent = '';
  } else if (ai && ai.status === 'failed') {
    labelEl.className = 'ai-label fail';
    labelEl.textContent = 'AI query failed';
    textEl.innerHTML = renderAI(ai.analysis || '');
    badgeEl.textContent = '';
  } else {
    labelEl.className = 'ai-label none';
    labelEl.textContent = 'No analysis';
    textEl.innerHTML = 'Re-run with <code>--tenant</code> and <code>--api-key</code> to query the XC AI assistant.';
    badgeEl.textContent = '';
  }

  document.getElementById('ai-divider').style.display = 'flex';
  if (!aiCollapsed)
    document.getElementById('ai-pane').style.display = 'block';

  showSNow(d);
}

// ── ServiceNow flyout ────────────────────────────────────────────────────────
// Set this to your ServiceNow instance base URL to make ticket numbers clickable
// e.g. 'https://yourcompany.service-now.com'
const SNOW_INSTANCE_URL = '';

const TYPE_COLORS = {
  INC: '#ef4444', CHG: '#f59e0b', RITM: '#8b5cf6', PRB: '#f87171',
  REQ: '#10b981', TASK: '#6366f1', SCTASK: '#6366f1', STASK: '#6366f1',
  CTASK: '#6366f1', CRQ: '#f59e0b',
};

let _snowTickets  = [];
let _snowIRuleName = '';

function _renderTickets(tickets) {
  if (!tickets.length) return '<div class="snow-empty">No ServiceNow references found.</div>';
  return tickets.map(t => {
    const color = TYPE_COLORS[t.ticket_type] || '#38bdf8';
    const href  = SNOW_INSTANCE_URL
      ? `${SNOW_INSTANCE_URL}/nav_to.do?uri=${encodeURIComponent(t.ticket_number)}`
      : null;
    const numEl = href
      ? `<a class="snow-num" href="${href}" target="_blank" rel="noopener">${t.ticket_number}</a>`
      : `<span class="snow-num">${t.ticket_number}</span>`;
    const ctx = t.context_snippet
      ? `<div class="snow-ctx">${t.context_snippet.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}</div>`
      : '';
    return `<div class="snow-ticket" style="border-left-color:${color}">
      <div class="snow-ticket-header">
        ${numEl}
        <span class="snow-type-badge" style="background:${color}22;color:${color}">${t.ticket_type}</span>
      </div>
      ${t.llm_summary ? `<div class="snow-summary">${t.llm_summary}</div>` : ''}
      ${ctx}
    </div>`;
  }).join('');
}

function showSNow(d) {
  const tickets  = d.servicenow_tickets || [];
  const trigBtn  = document.getElementById('snow-trigger-btn');
  const countEl  = document.getElementById('snow-trigger-count');

  _snowTickets   = tickets;
  _snowIRuleName = d.full || '';

  if (!tickets.length) {
    trigBtn.style.display = 'none';
    return;
  }
  countEl.textContent    = tickets.length;
  trigBtn.style.display  = 'inline-flex';
}

function openSNowFlyout() {
  document.getElementById('snow-flyout-badge').textContent  = _snowTickets.length;
  document.getElementById('snow-flyout-irule').textContent  = _snowIRuleName;
  document.getElementById('snow-flyout-body').innerHTML     = _renderTickets(_snowTickets);
  document.getElementById('snow-backdrop').classList.add('open');
  document.getElementById('snow-flyout').classList.add('open');
  document.body.style.overflow = 'hidden';
}

function closeSNowFlyout() {
  document.getElementById('snow-backdrop').classList.remove('open');
  document.getElementById('snow-flyout').classList.remove('open');
  document.body.style.overflow = '';
}

// Close on Escape key
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeSNowFlyout();
});

function jumpToDup(key) {
  const rd = DATA.irules[key];
  if (!rd) return;
  showCode({ full: rd.path, code: rd.code, host: rd.host,
             ai_analysis: rd.ai_analysis, content_hash: rd.content_hash,
             duplicate_keys: rd.duplicate_keys || [],
             irule_status: rd.irule_status, stats: rd.stats,
             stats_history: rd.stats_history || [] });
  const n = nodes.find(x => x.id === key);
  if (n) selectNode(n);
}

function copyCode() {
  navigator.clipboard.writeText(currentCode).then(() => {
    const btn = document.getElementById('copy-btn');
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
  });
}

window.addEventListener('resize', () => {
  W = panel.clientWidth; H = panel.clientHeight;
  sim.force('center', d3.forceCenter(W / 2, H / 2)).alpha(0.1).restart();
});

// ── Resizable dividers ───────────────────────────────────────────────────────
(function() {
  const handleV   = document.getElementById('resize-v');
  const codePanel = document.getElementById('code-panel');
  const aiDiv     = document.getElementById('ai-divider');
  const aiPane    = document.getElementById('ai-pane');

  let draggingV = false;
  let draggingH = false, hStartY = 0, hStartH = 0, hMoved = false;

  // ── Vertical handle (diagram ↔ code panel) ──
  handleV.addEventListener('mousedown', e => {
    draggingV = true;
    handleV.classList.add('dragging');
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
    e.preventDefault();
  });

  // ── Horizontal handle (source ↔ AI pane) ──
  // Snapshot the current rendered height so resize is delta-based — no jump on first move.
  aiDiv.addEventListener('mousedown', e => {
    hStartH   = aiPane.getBoundingClientRect().height || 220;
    hStartY   = e.clientY;
    hMoved    = false;
    draggingH = true;
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
    e.preventDefault();
  });

  document.addEventListener('mousemove', e => {
    if (draggingV) {
      const rect = document.querySelector('.main-area').getBoundingClientRect();
      const w = Math.min(Math.max(rect.right - e.clientX - 3, 280), rect.width - 220);
      codePanel.style.width = w + 'px';
    }
    if (draggingH) {
      const delta = hStartY - e.clientY;   // positive = drag up = grow ai pane
      if (Math.abs(delta) > 3) hMoved = true;
      const maxH = codePanel.getBoundingClientRect().height - 150;
      const newH = Math.min(Math.max(hStartH + delta, 60), maxH);
      aiPane.style.flex   = 'none';
      aiPane.style.height = newH + 'px';
    }
  });

  document.addEventListener('mouseup', () => {
    if (draggingV) { draggingV = false; handleV.classList.remove('dragging'); }
    if (draggingH) {
      draggingH = false;
      if (!hMoved) toggleAI();   // short click, no movement → collapse/expand
    }
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  });
})();

// ── Popout / fly-out panel ───────────────────────────────────────────────────
let popoutAICollapsed = false;

function popoutPanel() {
  const overlay  = document.getElementById('popout-overlay');
  const popTitle = document.getElementById('popout-title');
  const popCode  = document.getElementById('popout-code');
  const popAILbl = document.getElementById('popout-ai-label');
  const popAITxt = document.getElementById('popout-ai-text');
  const popAIDiv = document.getElementById('popout-ai-divider');
  const popAIPan = document.getElementById('popout-ai-pane');

  popTitle.textContent  = document.getElementById('rule-name-display').textContent;
  popCode.textContent   = currentCode;

  const ai = currentAI;
  if (ai && ai.status === 'success') {
    popAILbl.className   = 'ai-label ok';
    popAILbl.textContent = ai.provider ? (ai.model ? `${ai.provider} / ${ai.model}` : ai.provider) : 'AI Assistant';
    popAITxt.innerHTML   = renderAI(ai.analysis || '');
  } else if (ai && ai.status === 'failed') {
    popAILbl.className   = 'ai-label fail'; popAILbl.textContent = 'AI query failed';
    popAITxt.innerHTML   = renderAI(ai.analysis || '');
  } else {
    popAILbl.className   = 'ai-label none'; popAILbl.textContent = 'No analysis';
    popAITxt.innerHTML   = 'No AI analysis available for this rule.';
  }

  popoutAICollapsed = false;
  document.getElementById('popout-chevron').style.transform = '';
  popAIPan.classList.remove('collapsed');
  overlay.classList.add('open');

  // Make window draggable
  makeDraggable(document.getElementById('popout-window'), document.getElementById('popout-titlebar'));

  // Make AI pane resizable within popout
  makeVResize(popAIDiv, popAIPan, document.getElementById('popout-body'));
}

function closePopout() {
  document.getElementById('popout-overlay').classList.remove('open');
}

function togglePopoutAI() {
  popoutAICollapsed = !popoutAICollapsed;
  document.getElementById('popout-chevron').style.transform = popoutAICollapsed ? 'rotate(-90deg)' : '';
  document.getElementById('popout-ai-pane').classList.toggle('collapsed', popoutAICollapsed);
}

// Generic drag-to-move for an element
function makeDraggable(el, handle) {
  let ox = 0, oy = 0, sx = 0, sy = 0, active = false;
  el.style.position = 'relative';
  handle.addEventListener('mousedown', e => {
    active = true; sx = e.clientX; sy = e.clientY;
    ox = parseInt(el.style.left) || 0; oy = parseInt(el.style.top) || 0;
    document.body.style.userSelect = 'none';
  });
  document.addEventListener('mousemove', e => {
    if (!active) return;
    el.style.left = (ox + e.clientX - sx) + 'px';
    el.style.top  = (oy + e.clientY - sy) + 'px';
  });
  document.addEventListener('mouseup', () => { active = false; document.body.style.userSelect = ''; });
}

// Generic vertical resize for a pane via a drag handle (delta-based, no jump)
function makeVResize(handle, pane, container) {
  let active = false, startY = 0, startH = 0, moved = false;
  handle.addEventListener('mousedown', e => {
    startH = pane.getBoundingClientRect().height || 200;
    startY = e.clientY;
    moved  = false;
    active = true;
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
    e.preventDefault();
  });
  document.addEventListener('mousemove', e => {
    if (!active) return;
    const delta = startY - e.clientY;
    if (Math.abs(delta) > 3) moved = true;
    const maxH = container.getBoundingClientRect().height - 120;
    pane.style.flex   = 'none';
    pane.style.height = Math.min(Math.max(startH + delta, 60), maxH) + 'px';
  });
  document.addEventListener('mouseup', () => {
    if (!active) return;
    active = false;
    if (!moved) togglePopoutAI();
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  });
}

// ── Tab switching ────────────────────────────────────────────────────────────
let forceEverShown = false;

function switchTab(name) {
  document.getElementById('pane-force').style.display  = name === 'force'  ? 'flex' : 'none';
  document.getElementById('pane-sankey').classList.toggle('active', name === 'sankey');
  document.getElementById('pane-fleet').classList.toggle('active',  name === 'fleet');
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  if (name === 'force' && !forceEverShown) {
    forceEverShown = true;
    // Pane was hidden at script load so W/H were 0. Read true dimensions now
    // and give the sim a full restart so nodes spread into the real viewport.
    requestAnimationFrame(() => {
      W = panel.clientWidth;
      H = panel.clientHeight;
      sim.force('center', d3.forceCenter(W / 2, H / 2)).alpha(1).restart();
    });
  }
  if (name === 'sankey' && !sankeyBuilt) buildSankey();
  if (name === 'fleet'  && !fleetBuilt)  buildFleet();
}

// ── Fleet view ───────────────────────────────────────────────────────────────
let fleetBuilt = false;

// Roll-up priority: error > orphan > active > attached > unreachable
const STATUS_RANK = { error: 4, orphan: 3, active: 2, attached: 1, unreachable: 0 };

function buildFleetData() {
  return DATA.devices.map(dev => {
    if (dev.error) {
      return { host: dev.host, rolledStatus: 'unreachable', vsCount: 0,
               ruleCount: 0, sc: { error:0, orphan:0, active:0, attached:0 }, err: dev.error };
    }
    const ruleKeys = new Set();
    (dev.virtual_servers || []).forEach(vs =>
      (vs.rule_keys || []).forEach(rk => ruleKeys.add(rk)));
    // include orphans that belong to this device
    Object.entries(DATA.irules).forEach(([rk, rd]) => {
      if (rd.host === dev.host && rd.irule_status === 'orphan') ruleKeys.add(rk);
    });
    const sc = { error: 0, orphan: 0, active: 0, attached: 0 };
    ruleKeys.forEach(rk => {
      const st = (DATA.irules[rk] || {}).irule_status || 'attached';
      if (st in sc) sc[st]++;
    });
    let rolledStatus = 'attached';
    if (sc.active  > 0) rolledStatus = 'active';
    if (sc.orphan  > 0) rolledStatus = 'orphan';
    if (sc.error   > 0) rolledStatus = 'error';
    return { host: dev.host, rolledStatus,
             vsCount: (dev.virtual_servers || []).length,
             ruleCount: ruleKeys.size, sc };
  });
}

function focusDevice(host) {
  const firstTime = !forceEverShown;
  switchTab('force');   // may trigger sim restart on first visit

  function doZoom() {
    W = panel.clientWidth;
    H = panel.clientHeight;
    const n = nodes.find(d => d.type === 'device' && d.label === host);
    if (!n) return;
    // If the sim just started (first visit) nodes are still moving — use a
    // short settled delay so node.x/y reflect the in-progress layout.
    const nx = (n.x != null && Math.abs(n.x) > 1) ? n.x : W / 2;
    const ny = (n.y != null && Math.abs(n.y) > 1) ? n.y : H / 2;
    const scale = 1.8;
    svg.transition().duration(650)
       .call(zoomBehavior.transform,
             d3.zoomIdentity.translate(W / 2 - nx * scale, H / 2 - ny * scale).scale(scale));
    selectNode(n);
  }

  if (firstTime) {
    // Give the sim ~400 ms to spread nodes into the real viewport before zooming
    setTimeout(doZoom, 400);
  } else {
    requestAnimationFrame(doZoom);
  }
}

function buildFleet() {
  fleetBuilt = true;
  const allDevices = buildFleetData();

  let activeStatus = 'all';
  let activeSort   = 'status';
  let searchTerm   = '';

  const grid      = document.getElementById('fleet-grid');
  const countEl   = document.getElementById('fleet-counts');

  // status totals for toolbar badges
  const totals = { error: 0, orphan: 0, active: 0, attached: 0, unreachable: 0 };
  allDevices.forEach(d => { if (d.rolledStatus in totals) totals[d.rolledStatus]++; });
  countEl.textContent =
    `${allDevices.length} devices` +
    (totals.error       ? ` · ${totals.error} error`      : '') +
    (totals.orphan      ? ` · ${totals.orphan} orphan`     : '') +
    (totals.active      ? ` · ${totals.active} active`     : '') +
    (totals.unreachable ? ` · ${totals.unreachable} unreachable` : '');

  function sortDevices(arr) {
    return [...arr].sort((a, b) => {
      if (activeSort === 'status') {
        const diff = (STATUS_RANK[b.rolledStatus] || 0) - (STATUS_RANK[a.rolledStatus] || 0);
        return diff !== 0 ? diff : a.host.localeCompare(b.host);
      }
      if (activeSort === 'rules') return b.ruleCount - a.ruleCount || a.host.localeCompare(b.host);
      return a.host.localeCompare(b.host);  // 'name'
    });
  }

  function render() {
    const term = searchTerm.trim().toLowerCase();
    const filtered = sortDevices(allDevices.filter(d => {
      if (activeStatus !== 'all' && d.rolledStatus !== activeStatus) return false;
      if (term && !d.host.toLowerCase().includes(term)) return false;
      return true;
    }));

    if (filtered.length === 0) {
      grid.innerHTML = '<div class="fleet-empty">No devices match the current filter.</div>';
      return;
    }

    grid.innerHTML = filtered.map(d => {
      const dots = [];
      if (d.sc) {
        if (d.sc.error    > 0) dots.push(`<span class="ft-dot err">&#9679; ${d.sc.error}</span>`);
        if (d.sc.orphan   > 0) dots.push(`<span class="ft-dot orp">&#9679; ${d.sc.orphan}</span>`);
        if (d.sc.active   > 0) dots.push(`<span class="ft-dot act">&#9679; ${d.sc.active}</span>`);
        if (d.sc.attached > 0) dots.push(`<span class="ft-dot att">&#9679; ${d.sc.attached}</span>`);
      }
      const metaLine = d.rolledStatus === 'unreachable'
        ? `<div class="ft-meta" style="color:#6b7280">unreachable</div>`
        : `<div class="ft-meta">${d.ruleCount} iRule${d.ruleCount !== 1 ? 's' : ''} &middot; ${d.vsCount} VS</div>`;
      return `<div class="fleet-tile st-${d.rolledStatus}" onclick="focusDevice(${JSON.stringify(d.host)})" title="${d.host}">
        <div class="ft-host">${d.host}</div>
        ${metaLine}
        ${dots.length ? `<div class="ft-dots">${dots.join('')}</div>` : ''}
      </div>`;
    }).join('');
  }

  // ── toolbar wiring ──
  document.getElementById('fleet-search').addEventListener('input', e => {
    searchTerm = e.target.value;
    render();
  });

  document.querySelectorAll('#fleet-status-filters .flt-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      activeStatus = btn.dataset.s;
      document.querySelectorAll('#fleet-status-filters .flt-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      render();
    });
  });

  document.querySelectorAll('.fsort-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      activeSort = btn.dataset.sort;
      document.querySelectorAll('.fsort-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      render();
    });
  });

  render();
}

// ── Sankey diagram ───────────────────────────────────────────────────────────
let sankeyBuilt = false;

function buildSankey() {
  sankeyBuilt = true;
  const container = document.getElementById('pane-sankey');
  const W = container.clientWidth  || 1100;
  const H = container.clientHeight || 680;

  const outerSvg = d3.select('#sankey-svg').attr('width', W).attr('height', H);
  const skG = outerSvg.append('g');
  outerSvg.call(d3.zoom().scaleExtent([0.25, 5])
    .on('zoom', e => skG.attr('transform', e.transform)));

  // Build node/link arrays
  const rawNodes = [], rawLinks = [];
  const idx = {};
  let ni = 0;

  DATA.devices.filter(d => !d.error).forEach(dev => {
    const did = 'dev::' + dev.host;
    idx[did] = ni++;
    rawNodes.push({ id: did, name: dev.host, type: 'device' });

    (dev.virtual_servers || []).forEach(vs => {
      const vid = 'vs::' + dev.host + '::' + vs.full_path;
      if (!(vid in idx)) {
        idx[vid] = ni++;
        rawNodes.push({ id: vid, name: vs.name, type: 'vs' });
      }
      const rc = (vs.rule_keys || []).length;
      rawLinks.push({ source: idx[did], target: idx[vid], value: rc || 1 });

      (vs.rule_keys || []).forEach(rk => {
        if (!(rk in idx)) {
          idx[rk] = ni++;
          const rd = DATA.irules[rk];
          rawNodes.push({ id: rk, name: rd ? rd.path.replace(/^.*\//, '') : rk, type: 'irule' });
        }
        rawLinks.push({ source: idx[vid], target: idx[rk], value: 1 });
      });
    });
  });

  // Add orphan iRules connected directly to their device node
  Object.entries(DATA.irules).forEach(([rk, rd]) => {
    if (rd.irule_status !== 'orphan') return;
    const devId = 'dev::' + rd.host;
    if (!(devId in idx) || rk in idx) return;
    idx[rk] = ni++;
    rawNodes.push({ id: rk, name: rd.path.replace(/^.*\//, ''), type: 'irule' });
    rawLinks.push({ source: idx[devId], target: idx[rk], value: 0.4 });
  });

  const ML = 20, MR = 185, MT = 46, MB = 16;
  const sankey = d3.sankey()
    .nodeAlign(d3.sankeyLeft)
    .nodeWidth(18)
    .nodePadding(12)
    .extent([[ML, MT], [W - MR, H - MB]]);

  const { nodes, links } = sankey({
    nodes: rawNodes.map(d => Object.assign({}, d)),
    links: rawLinks.map(d => Object.assign({}, d)),
  });

  const C = { device: '#a78bfa', vs: '#60a5fa', irule: '#4ade80' };
  function skNodeColor(d) {
    if (d.type !== 'irule') return C[d.type];
    const rd = DATA.irules[d.id];
    return statusColor((rd && rd.irule_status) || 'attached');
  }
  const skTip = document.getElementById('sk-tooltip');

  // Links
  skG.append('g').attr('fill', 'none')
    .selectAll('path').data(links).join('path')
      .attr('d', d3.sankeyLinkHorizontal())
      .attr('stroke',         l => skNodeColor(l.source))
      .attr('stroke-width',   l => Math.max(1.5, l.width))
      .attr('stroke-opacity', 0.18)
      .on('mouseover', function(e, l) {
        d3.select(this).raise().attr('stroke-opacity', 0.55);
        skTip.style.opacity = 1;
        skTip.textContent = l.source.name + ' \u2192 ' + l.target.name;
      })
      .on('mousemove', e => { skTip.style.left=(e.clientX+14)+'px'; skTip.style.top=(e.clientY-10)+'px'; })
      .on('mouseout',  function() { d3.select(this).attr('stroke-opacity', 0.18); skTip.style.opacity=0; });

  // Nodes
  const ng = skG.append('g').selectAll('g').data(nodes).join('g');

  ng.append('rect')
    .attr('x', d => d.x0).attr('y', d => d.y0)
    .attr('width',  d => d.x1 - d.x0)
    .attr('height', d => Math.max(4, d.y1 - d.y0))
    .attr('fill', d => skNodeColor(d)).attr('rx', 3).attr('opacity', 0.85)
    .style('cursor', d => d.type === 'irule' ? 'pointer' : 'default')
    .on('click', (e, d) => {
      if (d.type !== 'irule') return;
      const rd = DATA.irules[d.id];
      if (rd) showCode({ full: rd.path, code: rd.code, host: rd.host,
                         ai_analysis: rd.ai_analysis, content_hash: rd.content_hash,
                         duplicate_keys: rd.duplicate_keys || [],
                         irule_status: rd.irule_status, stats: rd.stats,
                         stats_history: rd.stats_history || [] });
    })
    .on('mouseover', function(e, d) {
      d3.select(this).attr('opacity', 1);
      skTip.style.opacity = 1;
      const inn = links.filter(l => l.target === d).length;
      const out = links.filter(l => l.source === d).length;
      const rd  = d.type === 'irule' ? DATA.irules[d.id] : null;
      const st  = rd ? (rd.irule_status || 'attached') : null;
      const sc  = st ? statusColor(st) : C[d.type];
      let html  = `<b style="color:${sc}">${d.name}</b>`;
      if (d.type === 'irule') html += ' <span style="color:#4ade80;font-size:0.65rem">click to view</span>';
      html += `<br><span style="color:#64748b;font-size:0.68rem">${d.type.toUpperCase()}`;
      if (st) html += ` \u00b7 ${st}`;
      html += '</span>';
      if (rd && rd.stats) {
        const s = rd.stats;
        html += `<br><span style="font-size:0.7rem;color:#94a3b8">Exec: <b>${s.total_executions.toLocaleString()}</b>`;
        if (s.failures) html += ` <span style="color:#f87171">\u00b7 Fail: ${s.failures}</span>`;
        if (s.aborts)   html += ` <span style="color:#fb923c">\u00b7 Abort: ${s.aborts}</span>`;
        html += '</span>';
      }
      if (inn) html += `<br><span style="color:#475569;font-size:0.68rem">\u2190 ${inn} in</span>`;
      if (out) html += `<br><span style="color:#475569;font-size:0.68rem">\u2192 ${out} out</span>`;
      skTip.innerHTML = html;
    })
    .on('mousemove', e => { skTip.style.left=(e.clientX+14)+'px'; skTip.style.top=(e.clientY-10)+'px'; })
    .on('mouseout', function() { d3.select(this).attr('opacity', 0.85); skTip.style.opacity=0; });

  // Labels — iRules go left of node, everything else goes right
  ng.append('text')
    .attr('x', d => d.type === 'irule' ? d.x0 - 7 : d.x1 + 7)
    .attr('y', d => (d.y0 + d.y1) / 2)
    .attr('dy', '0.35em')
    .attr('text-anchor', d => d.type === 'irule' ? 'end' : 'start')
    .attr('font-size', '10.5px')
    .attr('fill', '#94a3b8')
    .text(d => d.name.length > 30 ? d.name.slice(0, 28) + '\u2026' : d.name);

  // Column header labels (one per type, at the average x of that column)
  const colX = {};
  nodes.forEach(n => {
    if (!colX[n.type]) colX[n.type] = [];
    colX[n.type].push((n.x0 + n.x1) / 2);
  });
  const HDR = { device: 'DEVICES', vs: 'VIRTUAL SERVERS', irule: 'IRULES' };
  const hdrEntries = Object.entries(colX).map(([type, xs]) =>
    ({ type, x: xs.reduce((a, b) => a + b, 0) / xs.length }));

  skG.append('g').selectAll('text').data(hdrEntries).join('text')
    .attr('x', d => d.x)
    .attr('y', MT - 12)
    .attr('text-anchor', 'middle')
    .attr('font-size', '10px').attr('font-weight', '700')
    .attr('fill', d => C[d.type]).attr('letter-spacing', '0.08em')
    .text(d => HDR[d.type] || d.type.toUpperCase());
}

// ── Default tab (must be last — all let variables must be declared first) ──
switchTab('fleet');
</script>
</body>
</html>
"""


def db_get_servicenow_refs(conn: sqlite3.Connection, content_hash: str) -> list:
    """Return all cached ServiceNow ticket references for an iRule."""
    try:
        rows = conn.execute(
            "SELECT ticket_number, ticket_type, context_snippet, llm_summary "
            "FROM servicenow_refs WHERE content_hash=? ORDER BY ticket_number",
            (content_hash,),
        ).fetchall()
        return [dict(r) for r in rows]
    except sqlite3.OperationalError:
        return []  # table not yet created (irule_rag.py never run)


def build_html(data: dict, conn: sqlite3.Connection | None = None) -> str:
    # Enrich iRule entries with ServiceNow refs if DB connection provided.
    # NOTE: data["irules"] is keyed by irule_key (host::path), NOT content_hash.
    #       The actual SHA-256 content_hash is inside each entry dict.
    if conn is not None:
        for entry in data.get("irules", {}).values():
            chash = entry.get("content_hash")
            if chash:
                refs = db_get_servicenow_refs(conn, chash)
                if refs:
                    entry["servicenow_tickets"] = refs

    # Escape </ so iRules containing </script> or </style> can't break the HTML parser.
    # \/ is valid JSON and browsers treat it identically to /.
    safe_json = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    return HTML_TEMPLATE.replace("__DATA__", safe_json)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Discover BIG-IP iRules and generate an HTML diagram viewer.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  # discover from a single device
  %(prog)s --host 10.1.1.1 -u admin -p secret

  # discover from a list of devices
  %(prog)s --hosts-file devices.txt -u admin -p secret

  # upload to XC and query AI assistant (api-key via env var)
  export F5_XC_API_KEY=your_token
  %(prog)s --hosts-file devices.txt -u admin -p secret -t mycompany

  # all XC options explicit
  %(prog)s --host 10.1.1.1 -u admin -p secret \\
           -t mycompany -n system -k your_token -r 20 -c 3
""",
    )

    parser.add_argument("--rebuild-html", action="store_true",
                        help="Re-generate irule_viewer.html from an existing manifest.json "
                             "(no BIG-IP connection required). Combine with --output-dir if "
                             "your output is not in the default location.")
    parser.add_argument("--stats-only", action="store_true",
                        help="Refresh execution stats from BIG-IP without a full re-discovery. "
                             "Only records rows whose stats changed since the last run. "
                             "Requires --host/--hosts-file, --username, --password.")

    src = parser.add_mutually_exclusive_group()
    src.add_argument("--host",       metavar="HOST",
                     help="Single BIG-IP hostname or IP address")
    src.add_argument("--hosts-file", metavar="FILE",
                     help="Text file with one BIG-IP hostname/IP per line (# comments ok)")

    parser.add_argument("--username",  "-u", default=None, help="BIG-IP username")
    parser.add_argument("--password",  "-p", default=None, help="BIG-IP password")
    parser.add_argument("--output-dir","-o", default="irule_output",
                        help="Output directory (default: irule_output)")
    parser.add_argument("--partition",       default=None,
                        help="Limit to a specific partition, e.g. Common")
    parser.add_argument("--no-html",   action="store_true",
                        help="Skip HTML viewer generation")
    parser.add_argument("--include-orphans", action="store_true",
                        help="Also discover iRules that exist on BIG-IP but are not "
                             "attached to any virtual server (default: off — BIG-IP "
                             "ships with hundreds of system iRules that inflate the count)")

    xc = parser.add_argument_group("F5 Distributed Cloud (optional — matches irule-ai-assistant flags)")
    xc.add_argument("-t", "--tenant",       metavar="TENANT",
                    help="F5 XC tenant name, e.g. mycompany")
    xc.add_argument("-n", "--namespace",    metavar="NS", default="system",
                    help="F5 XC namespace (default: system)")
    xc.add_argument("-k", "--api-key",      metavar="KEY", default=None,
                    help="F5 XC API key (overrides F5_XC_API_KEY env var)")
    xc.add_argument("-c", "--max-concurrent", metavar="N", type=int, default=3,
                    help="Max concurrent XC requests (default: 3)")
    xc.add_argument("-r", "--rate-limit",      metavar="SECS", type=float, default=20.0,
                    help="Minimum seconds between AI query requests (default: 20)")
    xc.add_argument("-q", "--max-query-chars", metavar="N",    type=int,   default=8000,
                    help="Max iRule characters sent per AI query — truncates if larger (default: 8000)")
    xc.add_argument("--upload", action="store_true",
                    help="Phase 3: upload discovered iRules to the XC iRule library")
    xc.add_argument("--upload-namespace", metavar="NS", default=None,
                    help="XC namespace for the iRule library (default: same as --namespace)")
    xc.add_argument("--ai-provider", metavar="PROVIDER", default=None,
                    help="AI analysis provider: xc, anthropic, openai (env: AI_PROVIDER)")
    xc.add_argument("--ai-model", metavar="MODEL", default=None,
                    help="AI model name override (env: AI_MODEL; default per provider)")
    xc.add_argument("--ai-key", metavar="KEY", default=None,
                    help="API key for non-XC providers (env: AI_API_KEY)")
    xc.add_argument("--debug", action="store_true",
                    help="Enable debug logging")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    # ── --rebuild-html: regenerate viewer from existing manifest, then exit ────
    if args.rebuild_html:
        out_dir       = Path(args.output_dir)
        manifest_path = out_dir / "manifest.json"
        if not manifest_path.exists():
            sys.exit(f"[!] manifest.json not found in {out_dir}. "
                     "Run a discovery first or use --output-dir to point at the right folder.")
        print(f"[*] Loading manifest → {manifest_path}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        irules   = manifest.get("irules", {})

        # Open DB (creates it if this is first run after migration)
        conn = open_db(out_dir)
        init_db(conn)
        _migrate_json_to_db(conn, out_dir)

        # Back-fill hashes / dedup for old manifests
        needs_hash = any(v.get("content_hash") is None and v.get("code") for v in irules.values())
        if needs_hash:
            for entry in irules.values():
                if entry.get("content_hash") is None and entry.get("code"):
                    entry["content_hash"] = content_hash(entry["code"])
                if "duplicate_keys" not in entry:
                    entry["duplicate_keys"] = []
            dups = find_duplicate_irules(irules)
            if dups:
                print(f"[~] Back-filled hashes · {dups} duplicate(s) detected")

        # Back-fill xc_library from DB
        xc_entries = db_load_upload_registry(conn)
        lib_filled = 0
        for entry in irules.values():
            chash   = entry.get("content_hash")
            new_val = xc_entries.get(chash) if chash else None
            if entry.get("xc_library") != new_val:
                entry["xc_library"] = new_val
                lib_filled += 1
        if lib_filled:
            print(f"[~] Back-filled xc_library on {lib_filled} iRule(s) from DB")

        # Back-fill stats_history and irule_status from DB
        for entry in irules.values():
            chash = entry.get("content_hash")
            if chash:
                entry["stats_history"] = db_get_stats_history(conn, chash)
            if not entry.get("irule_status"):
                entry["irule_status"] = compute_irule_status(entry)

        if lib_filled or needs_hash:
            manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))

        html_path = out_dir / "irule_viewer.html"
        html_path.write_text(build_html(manifest, conn), encoding="utf-8")
        print(f"[+] HTML viewer rebuilt → {html_path}")
        conn.close()
        webbrowser.open(html_path.resolve().as_uri())
        return

    # ── --stats-only: refresh execution stats without full re-discovery ────────
    if args.stats_only:
        if not args.host and not args.hosts_file:
            parser.error("--stats-only requires --host or --hosts-file")
        if not args.username:
            parser.error("--stats-only requires --username / -u")
        if not args.password:
            parser.error("--stats-only requires --password / -p")
        out_dir = Path(args.output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        conn = open_db(out_dir)
        init_db(conn)
        _migrate_json_to_db(conn, out_dir)
        hosts = ([args.host] if args.host else load_hosts_file(args.hosts_file))
        print(f"\n{'─'*55}")
        print(f"  Stats refresh — {len(hosts)} device(s)")
        print(f"{'─'*55}")
        total_updated = 0
        for host in hosts:
            print(f"\n[*] {host} …", flush=True)
            result = collect_irule_stats(host, args.username, args.password,
                                         out_dir, partition=args.partition,
                                         db_conn=conn)
            if "error" in result:
                print(f"[!] {host}: {result['error']}")
            else:
                print(f"[+] {host}: {result['checked']} checked · "
                      f"{result['new']} new · {result['updated']} updated · "
                      f"{result['unchanged']} unchanged · {result['errors']} with errors")
                total_updated += result["updated"] + result["new"]
        conn.close()
        if total_updated:
            print(f"\n[~] {total_updated} stat change(s) recorded — "
                  "run --rebuild-html to refresh the viewer")
        else:
            print("\n[✓] All stats unchanged since last run")
        return

    # Normal discovery mode — --host/--hosts-file and credentials are required
    if not args.host and not args.hosts_file:
        parser.error("one of --host or --hosts-file is required (or use --rebuild-html)")
    if not args.username:
        parser.error("--username / -u is required")
    if not args.password:
        parser.error("--password / -p is required")

    # ── Resolve XC API key and build xc_cfg ──────────────────────────────────
    api_key = args.api_key or os.environ.get("F5_XC_API_KEY")

    xc_cfg: dict | None = None
    if args.tenant and not api_key:
        parser.error("--tenant requires --api-key or the F5_XC_API_KEY environment variable")
    if api_key and not args.tenant:
        parser.error("--api-key requires --tenant")
    if args.tenant and api_key:
        xc_cfg = {
            "tenant":           args.tenant,
            "namespace":        args.namespace,
            "api_token":        api_key,
            "max_concurrent":   args.max_concurrent,
            "rate_limit":       args.rate_limit,
            "max_query_chars":  args.max_query_chars,
        }
        print(f"[*] XC integration enabled — tenant={args.tenant} namespace={args.namespace}")

    # ── Resolve AI provider / model / key ────────────────────────────────────
    ai_provider = (args.ai_provider or os.environ.get("AI_PROVIDER") or
                   ("xc" if xc_cfg else None))
    ai_model    = args.ai_model or os.environ.get("AI_MODEL") or None
    ai_raw_key  = args.ai_key or os.environ.get("AI_API_KEY") or None

    ai_cfg: dict | None = None
    if ai_provider:
        if ai_provider not in _PROVIDER_FN:
            parser.error(f"--ai-provider must be one of: {', '.join(_PROVIDER_FN)}")
        if ai_provider == "xc":
            if not xc_cfg:
                parser.error("--ai-provider xc requires --tenant and --api-key / F5_XC_API_KEY")
            ai_cfg = {**xc_cfg, "provider": "xc", "model": None,
                      "api_key": xc_cfg["api_token"]}
        else:
            # anthropic or openai — resolve provider-specific env var as fallback
            env_key = ("ANTHROPIC_API_KEY" if ai_provider == "anthropic"
                       else "OPENAI_API_KEY")
            resolved_key = ai_raw_key or os.environ.get(env_key)
            if not resolved_key:
                parser.error(
                    f"--ai-provider {ai_provider} requires --ai-key, AI_API_KEY, "
                    f"or {env_key} environment variable"
                )
            ai_cfg = {
                "provider":        ai_provider,
                "model":           ai_model or _AI_DEFAULT_MODELS.get(ai_provider),
                "api_key":         resolved_key,
                "max_query_chars": args.max_query_chars,
            }
        model_label = ai_cfg.get("model") or "(provider default)"
        print(f"[*] AI analysis enabled — provider={ai_provider} model={model_label}")

    hosts: list[str] = ([args.host] if args.host
                        else load_hosts_file(args.hosts_file))

    out_dir    = Path(args.output_dir)
    irules_dir = out_dir / "irules"
    irules_dir.mkdir(parents=True, exist_ok=True)

    # ── Open SQLite DB (create + migrate on first run) ───────────────────────
    conn = open_db(out_dir)
    init_db(conn)
    _migrate_json_to_db(conn, out_dir)

    irules_data: dict[str, dict] = {}
    device_records: list[dict]   = []

    # ── Phase 1: download iRules + stats from all BIG-IP devices ────────────
    print(f"\n{'─'*55}")
    print(f"  Phase 1 — BIG-IP discovery ({len(hosts)} device(s))")
    print(f"{'─'*55}")
    for host in hosts:
        rec = discover_device(host, args.username, args.password,
                              args.partition, irules_dir, irules_data,
                              include_orphans=args.include_orphans)
        device_records.append(rec)

    # ── Deduplication: hash all iRules, find identical content ───────────────
    dup_count = find_duplicate_irules(irules_data)
    if dup_count:
        print(f"\n[~] Duplicates: {dup_count} iRule(s) share content with at least one other rule")

    # ── Record stats to DB and compute final status ──────────────────────────
    import datetime
    run_at = datetime.datetime.utcnow().isoformat() + "Z"
    for entry in irules_data.values():
        chash = entry.get("content_hash")
        stats = entry.get("stats")
        if chash and stats:
            db_record_stats(conn, chash, entry["host"], entry["path"], run_at,
                            stats["total_executions"], stats["failures"], stats["aborts"],
                            json.dumps(stats.get("events", {})))
            entry["stats_history"] = db_get_stats_history(conn, chash)
        entry["irule_status"] = compute_irule_status(entry)

    # ── Back-fill xc_library from DB (even without --upload) ────────────────
    xc_entries = db_load_upload_registry(conn)
    for entry in irules_data.values():
        chash = entry.get("content_hash")
        if chash and not entry.get("xc_library"):
            entry["xc_library"] = xc_entries.get(chash)

    # ── Phase 2: AI analysis (rate-limited for XC) ──────────────────────────
    if ai_cfg:
        provider = ai_cfg.get("provider", "xc")
        model    = ai_cfg.get("model") or _AI_DEFAULT_MODELS.get(provider)
        rl       = ai_cfg.get("rate_limit", 0)
        label    = f"{provider}" + (f"/{model}" if model else "")
        rl_note  = f"  (rate-limit={rl}s)" if rl else ""
        print(f"\n{'─'*55}")
        print(f"  Phase 2 — AI analysis via {label}{rl_note}")
        print(f"{'─'*55}")
        ai_enrich_irules(irules_data, irules_dir, ai_cfg, db_conn=conn)

    # ── Phase 3: XC iRule library upload ────────────────────────────────────
    if xc_cfg and args.upload:
        upload_ns = args.upload_namespace or xc_cfg["namespace"]
        xc_cfg["upload_namespace"] = upload_ns
        print(f"\n{'─'*55}")
        print(f"  Phase 3 — XC iRule library upload  (namespace={upload_ns})")
        print(f"{'─'*55}")
        xc_upload_irules(irules_data, out_dir, xc_cfg, db_conn=conn)

    conn.close()

    manifest = {"devices": device_records, "irules": irules_data}
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(f"\n[+] Manifest written → {manifest_path}")
    print(f"[+] Database → {out_dir / _DB_FILE}")

    if not args.no_html:
        conn2 = open_db(out_dir)
        html_path = out_dir / "irule_viewer.html"
        html_path.write_text(build_html(manifest, conn2), encoding="utf-8")
        conn2.close()
        print(f"[+] HTML viewer written → {html_path}")
        webbrowser.open(html_path.resolve().as_uri())

    total_vs    = sum(len(d["virtual_servers"]) for d in device_records)
    total_rules = len(irules_data)
    ok_devs     = sum(1 for d in device_records if not d.get("error"))
    orphans     = sum(1 for r in irules_data.values() if r.get("irule_status") == "orphan")
    errors      = sum(1 for r in irules_data.values() if r.get("irule_status") == "error")
    ai_ok       = sum(1 for r in irules_data.values()
                      if r.get("ai_analysis") and r["ai_analysis"]["status"] == "success")

    print(f"\n[✓] Done — {ok_devs}/{len(hosts)} device(s) · {total_vs} VS · {total_rules} iRules", end="")
    if orphans: print(f" · {orphans} orphaned", end="")
    if errors:  print(f" · {errors} with errors", end="")
    if ai_cfg:  print(f" · {ai_ok}/{total_rules} AI analyses", end="")
    print()


if __name__ == "__main__":
    main()
