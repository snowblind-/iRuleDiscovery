#!/usr/bin/env python3
"""
irule_rag.py — Local RAG + ServiceNow reference scanner for iRule Discovery

Uses a locally-running Ollama instance (Llama 3 + nomic-embed-text) to:
  1. Build a vector embedding index of all discovered iRules
  2. Scan every iRule for ServiceNow ticket references (INC, CHG, RITM, …)
     and use the LLM to summarise the purpose of each ticket in context
  3. Cache results in irule_discovery.db  →  visible in the viewer under
     each iRule's AI Analysis panel

Usage:
  python3 irule_rag.py --scan-snow             # Find + summarise SNow tickets
  python3 irule_rag.py --build-index           # Build / refresh embedding index
  python3 irule_rag.py --query "which iRules handle JWT auth?"
  python3 irule_rag.py --show-snow             # Print cached SNow results
  python3 irule_rag.py --rebuild-html          # Re-generate viewer with SNow data

Options:
  --output-dir DIR       irule_output directory (default: irule_output)
  --ollama-url URL       Ollama base URL (default: http://localhost:11434)
  --embed-model MODEL    Embedding model (default: nomic-embed-text)
  --gen-model MODEL      Generation model (default: llama3)
  --top-k N              Results returned by --query (default: 5)
  --no-llm               Skip LLM enrichment in --scan-snow (regex only)
  --force                Re-scan / re-embed even if already cached
"""

from __future__ import annotations

import argparse
import datetime
import json
import math
import re
import sqlite3
import struct
import sys
from pathlib import Path
from typing import Optional

import requests

# ── Constants ─────────────────────────────────────────────────────────────────

_DB_FILE       = "irule_discovery.db"
_MANIFEST_FILE = "manifest.json"
_VIEWER_FILE   = "irule_viewer.html"

DEFAULT_OLLAMA  = "http://localhost:11434"
DEFAULT_EMBED   = "nomic-embed-text"
DEFAULT_GEN     = "llama3"

# ServiceNow ticket number prefixes — case-insensitive
SNOW_PATTERN = re.compile(
    r'\b(INC|CHG|RITM|SCTASK|STASK|CTASK|TASK|REQ|PRB|CRQ|PROBLEM)\d{4,12}\b',
    re.IGNORECASE,
)

SNOW_SCAN_PROMPT = """\
You are reviewing a line from an F5 BIG-IP iRule TCL script.

The line or comment below contains a reference to ServiceNow ticket {ticket}:
  {context}

In one concise sentence (max 20 words), describe what change or fix this \
ServiceNow ticket likely relates to in the context of this iRule.
Do not repeat the ticket number. Do not say "ServiceNow". Be specific."""

RAG_SYSTEM = """\
You are an expert F5 BIG-IP iRule analyst. Answer questions about the iRules \
provided. Be concise and technical. Cite iRule names when relevant."""

# ── Env / .env loader (mirrors irule_discovery.py) ───────────────────────────

def _load_env(path: Optional[Path] = None) -> None:
    env_path = path or (Path(__file__).parent / ".env")
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip(); val = val.strip().strip('"').strip("'")
        import os
        if key and key not in __import__("os").environ:
            __import__("os").environ[key] = val

_load_env()

# ── SQLite helpers ─────────────────────────────────────────────────────────────

def open_db(out_dir: Path) -> sqlite3.Connection:
    db_path = out_dir / _DB_FILE
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_rag_tables(conn: sqlite3.Connection) -> None:
    conn.executescript("""
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

    CREATE TABLE IF NOT EXISTS irule_embeddings (
        content_hash  TEXT PRIMARY KEY,
        irule_path    TEXT NOT NULL,
        embed_model   TEXT NOT NULL,
        embedding     BLOB NOT NULL,
        embedded_at   TEXT NOT NULL
    );
    """)
    conn.commit()


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

# ── Embedding helpers ─────────────────────────────────────────────────────────

def _pack(vec: list[float]) -> bytes:
    return struct.pack(f"{len(vec)}f", *vec)


def _unpack(data: bytes) -> list[float]:
    n = len(data) // 4
    return list(struct.unpack(f"{n}f", data))


def _cosine(a: list[float], b: list[float]) -> float:
    dot  = sum(x * y for x, y in zip(a, b))
    ma   = math.sqrt(sum(x * x for x in a))
    mb   = math.sqrt(sum(x * x for x in b))
    return dot / (ma * mb + 1e-10)

# ── Ollama client ─────────────────────────────────────────────────────────────

class OllamaClient:
    def __init__(self, base_url: str = DEFAULT_OLLAMA,
                 embed_model: str = DEFAULT_EMBED,
                 gen_model: str   = DEFAULT_GEN) -> None:
        self.base        = base_url.rstrip("/")
        self.embed_model = embed_model
        self.gen_model   = gen_model

    def _check(self) -> None:
        try:
            r = requests.get(f"{self.base}/api/tags", timeout=5)
            r.raise_for_status()
        except Exception as exc:
            sys.exit(f"[!] Ollama not reachable at {self.base}: {exc}\n"
                     "    Start it with: ollama serve")

    def embed(self, text: str) -> list[float]:
        resp = requests.post(
            f"{self.base}/api/embeddings",
            json={"model": self.embed_model, "prompt": text[:8000]},
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["embedding"]

    def generate(self, prompt: str, system: str = "") -> str:
        payload: dict = {
            "model":  self.gen_model,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system
        resp = requests.post(f"{self.base}/api/generate", json=payload, timeout=120)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()

    def chat_stream(self, messages: list[dict]) -> None:
        """Stream a chat response to stdout."""
        resp = requests.post(
            f"{self.base}/api/chat",
            json={"model": self.gen_model, "messages": messages, "stream": True},
            stream=True,
            timeout=180,
        )
        resp.raise_for_status()
        for line in resp.iter_lines():
            if not line:
                continue
            chunk = json.loads(line)
            if token := chunk.get("message", {}).get("content"):
                print(token, end="", flush=True)
            if chunk.get("done"):
                break
        print()  # newline after stream

# ── Manifest loader ───────────────────────────────────────────────────────────

def load_manifest(out_dir: Path) -> dict:
    path = out_dir / _MANIFEST_FILE
    if not path.exists():
        sys.exit(f"[!] manifest.json not found in {out_dir}. "
                 "Run irule_discovery.py first.")
    return json.loads(path.read_text(encoding="utf-8"))


def irules_from_manifest(manifest: dict) -> list[dict]:
    """Return a flat list of iRule entries with content_hash included.

    The manifest dict is keyed by irule_key (host::path), NOT by content_hash.
    Each entry already carries a 'content_hash' field (SHA-256 of the source).
    We preserve that and fall back to the key only for legacy manifests that
    pre-date the content_hash field.
    """
    result = []
    for key, entry in manifest.get("irules", {}).items():
        e = dict(entry)
        if not e.get("content_hash"):
            e["content_hash"] = key   # legacy fallback only
        result.append(e)
    return result

# ── ServiceNow scanner ────────────────────────────────────────────────────────

def _context_for_match(code: str, match: re.Match, radius: int = 200) -> str:
    """Return up to `radius` chars around a regex match, trimmed to line boundaries."""
    start = code.rfind("\n", 0, match.start())
    start = 0 if start == -1 else start + 1
    end   = code.find("\n", match.end())
    end   = len(code) if end == -1 else end
    # Extend to a few surrounding lines for context
    for _ in range(2):
        prev = code.rfind("\n", 0, max(0, start - 1))
        start = 0 if prev == -1 else prev + 1
    snippet = code[start:end].strip()
    return snippet[:400]


def scan_irule_for_snow(code: str) -> list[dict]:
    """Return all ServiceNow ticket references found in iRule source."""
    seen: set[str] = set()
    tickets: list[dict] = []
    for m in SNOW_PATTERN.finditer(code):
        ticket = m.group(0).upper()
        if ticket in seen:
            continue
        seen.add(ticket)
        t_type = re.match(r"[A-Z]+", ticket).group()
        tickets.append({
            "ticket_number":   ticket,
            "ticket_type":     t_type,
            "context_snippet": _context_for_match(code, m),
            "llm_summary":     None,
        })
    return tickets


def enrich_with_llm(ticket: dict, llm: OllamaClient) -> str:
    prompt = SNOW_SCAN_PROMPT.format(
        ticket=ticket["ticket_number"],
        context=ticket["context_snippet"][:300],
    )
    try:
        return llm.generate(prompt)
    except Exception as exc:
        return f"(LLM error: {exc})"


def run_snow_scan(out_dir: Path, llm: OllamaClient,
                  use_llm: bool = True, force: bool = False) -> None:
    manifest = load_manifest(out_dir)
    irules   = irules_from_manifest(manifest)
    conn     = open_db(out_dir)
    init_rag_tables(conn)

    total_found = 0
    total_new   = 0

    for entry in irules:
        chash     = entry["content_hash"]
        path      = entry.get("path", chash)
        code      = entry.get("code", "")

        if not code:
            # Try reading from .tcl file
            name     = path.rsplit("/", 1)[-1]
            tcl_path = out_dir / f"{name}.tcl"
            if tcl_path.exists():
                code = tcl_path.read_text(encoding="utf-8", errors="replace")

        if not code:
            continue

        tickets = scan_irule_for_snow(code)
        if not tickets:
            continue

        total_found += len(tickets)
        print(f"  {path}: {len(tickets)} ticket(s) found")

        for t in tickets:
            # Check if already cached
            existing = conn.execute(
                "SELECT llm_summary FROM servicenow_refs "
                "WHERE content_hash=? AND ticket_number=?",
                (chash, t["ticket_number"]),
            ).fetchone()

            if existing and not force:
                continue  # already cached

            if use_llm:
                print(f"    → {t['ticket_number']} — enriching with LLM …", end="", flush=True)
                t["llm_summary"] = enrich_with_llm(t, llm)
                print(f" done")

            conn.execute(
                "INSERT OR REPLACE INTO servicenow_refs "
                "(content_hash, irule_path, ticket_number, ticket_type, "
                " context_snippet, llm_summary, found_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (chash, path, t["ticket_number"], t["ticket_type"],
                 t["context_snippet"], t.get("llm_summary"), _now()),
            )
            conn.commit()
            total_new += 1

    print(f"\n✓ Scan complete — {total_found} ticket reference(s) across "
          f"{len(irules)} iRules, {total_new} new/updated cache entries")

# ── Embedding index ───────────────────────────────────────────────────────────

def run_build_index(out_dir: Path, llm: OllamaClient, force: bool = False) -> None:
    manifest = load_manifest(out_dir)
    irules   = irules_from_manifest(manifest)
    conn     = open_db(out_dir)
    init_rag_tables(conn)

    new_count = 0
    for i, entry in enumerate(irules, 1):
        chash = entry["content_hash"]
        path  = entry.get("path", chash)
        code  = entry.get("code", "")

        if not code:
            name     = path.rsplit("/", 1)[-1]
            tcl_path = out_dir / f"{name}.tcl"
            if tcl_path.exists():
                code = tcl_path.read_text(encoding="utf-8", errors="replace")
        if not code:
            continue

        existing = conn.execute(
            "SELECT 1 FROM irule_embeddings WHERE content_hash=? AND embed_model=?",
            (chash, llm.embed_model),
        ).fetchone()

        if existing and not force:
            continue

        print(f"  [{i}/{len(irules)}] Embedding {path} …", end="", flush=True)
        text = f"iRule: {path}\n\n{code[:6000]}"
        vec  = llm.embed(text)
        conn.execute(
            "INSERT OR REPLACE INTO irule_embeddings "
            "(content_hash, irule_path, embed_model, embedding, embedded_at) "
            "VALUES (?,?,?,?,?)",
            (chash, path, llm.embed_model, _pack(vec), _now()),
        )
        conn.commit()
        new_count += 1
        print(" ok")

    print(f"\n✓ Index built — {new_count} new embeddings "
          f"({len(irules) - new_count} already cached)")

# ── RAG query ─────────────────────────────────────────────────────────────────

def run_query(question: str, out_dir: Path, llm: OllamaClient,
              top_k: int = 5) -> None:
    conn = open_db(out_dir)
    init_rag_tables(conn)

    # Load all embeddings
    rows = conn.execute(
        "SELECT content_hash, irule_path, embedding FROM irule_embeddings "
        "WHERE embed_model=?", (llm.embed_model,)
    ).fetchall()

    if not rows:
        print("[!] No embeddings found. Run --build-index first.")
        return

    print(f"Embedding question against {len(rows)} indexed iRules …")
    q_vec = llm.embed(question)

    # Cosine similarity ranking
    scored = sorted(
        [(row["irule_path"], _cosine(q_vec, _unpack(row["embedding"])),
          row["content_hash"])
         for row in rows],
        key=lambda x: x[1], reverse=True,
    )[:top_k]

    print(f"\nTop {top_k} most relevant iRules:")
    for rank, (path, score, _) in enumerate(scored, 1):
        print(f"  {rank}. {path}  (similarity {score:.3f})")

    # Load source for top-K iRules
    manifest = load_manifest(out_dir)
    irule_map = {v["content_hash"] if isinstance(k, int) else k: v
                 for k, v in manifest.get("irules", {}).items()}

    context_parts = []
    for path, score, chash in scored:
        entry = irule_map.get(chash, {})
        code  = entry.get("code", "")
        if not code:
            name     = path.rsplit("/", 1)[-1]
            tcl_path = out_dir / f"{name}.tcl"
            if tcl_path.exists():
                code = tcl_path.read_text(encoding="utf-8", errors="replace")
        context_parts.append(f"--- iRule: {path} ---\n{code[:2000]}")

    context = "\n\n".join(context_parts)
    messages = [
        {"role": "system",    "content": RAG_SYSTEM},
        {"role": "user",      "content": f"Context iRules:\n{context}\n\nQuestion: {question}"},
    ]

    print(f"\n{'─'*60}")
    llm.chat_stream(messages)

# ── Show cached SNow results ──────────────────────────────────────────────────

def run_show_snow(out_dir: Path) -> None:
    conn = open_db(out_dir)
    init_rag_tables(conn)
    rows = conn.execute(
        "SELECT irule_path, ticket_number, ticket_type, context_snippet, "
        "llm_summary, found_at FROM servicenow_refs ORDER BY irule_path, ticket_number"
    ).fetchall()

    if not rows:
        print("No ServiceNow references cached. Run --scan-snow first.")
        return

    current_path = None
    for row in rows:
        if row["irule_path"] != current_path:
            current_path = row["irule_path"]
            print(f"\n{'─'*60}")
            print(f"iRule: {current_path}")
        print(f"  [{row['ticket_type']}] {row['ticket_number']}")
        if row["context_snippet"]:
            for line in row["context_snippet"].splitlines()[:3]:
                print(f"    {line}")
        if row["llm_summary"]:
            print(f"    → {row['llm_summary']}")
    print(f"\n{len(rows)} ticket reference(s) total")

# ── Rebuild HTML with SNow data ───────────────────────────────────────────────

def run_rebuild_html(out_dir: Path) -> None:
    """Reload manifest, enrich with SNow refs from DB, rebuild viewer."""
    sys.path.insert(0, str(Path(__file__).parent))
    try:
        import irule_discovery as ird
    except ImportError as exc:
        sys.exit(f"[!] Could not import irule_discovery: {exc}")

    manifest_path = out_dir / _MANIFEST_FILE
    if not manifest_path.exists():
        sys.exit(f"[!] manifest.json not found in {out_dir}")

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    conn = open_db(out_dir)
    init_rag_tables(conn)

    # Enrich each iRule entry with SNow refs.
    # data["irules"] is keyed by irule_key (host::path); the actual SHA-256
    # content_hash is stored inside each entry dict.
    enriched = 0
    for entry in data.get("irules", {}).values():
        chash = entry.get("content_hash")
        if not chash:
            continue
        rows = conn.execute(
            "SELECT ticket_number, ticket_type, context_snippet, llm_summary "
            "FROM servicenow_refs WHERE content_hash=? ORDER BY ticket_number",
            (chash,),
        ).fetchall()
        if rows:
            entry["servicenow_tickets"] = [dict(r) for r in rows]
            enriched += 1

    html = ird.build_html(data)
    viewer = out_dir / _VIEWER_FILE
    viewer.write_text(html, encoding="utf-8")
    print(f"✓ Viewer rebuilt — {enriched} iRule(s) with ServiceNow references")
    print(f"  → {viewer}")

# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(
        description="Local Ollama RAG + ServiceNow scanner for iRule Discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  # Scan all iRules for ServiceNow ticket references + LLM summaries
  python3 irule_rag.py --scan-snow

  # Scan without LLM enrichment (regex only, fast)
  python3 irule_rag.py --scan-snow --no-llm

  # Build the semantic embedding index
  python3 irule_rag.py --build-index

  # Ask a natural-language question about your iRules
  python3 irule_rag.py --query "which iRules validate JWT tokens?"

  # Print all cached ServiceNow ticket references
  python3 irule_rag.py --show-snow

  # Rebuild the HTML viewer to include ServiceNow data
  python3 irule_rag.py --rebuild-html
""",
    )
    p.add_argument("--scan-snow",   action="store_true", help="Scan for ServiceNow ticket refs")
    p.add_argument("--build-index", action="store_true", help="Build vector embedding index")
    p.add_argument("--query",       metavar="Q",         help="Natural-language RAG query")
    p.add_argument("--show-snow",   action="store_true", help="Print cached SNow results")
    p.add_argument("--rebuild-html",action="store_true", help="Rebuild viewer with SNow data")
    p.add_argument("--output-dir",  "-o", default="irule_output", metavar="DIR")
    p.add_argument("--ollama-url",  default=DEFAULT_OLLAMA,  metavar="URL")
    p.add_argument("--embed-model", default=DEFAULT_EMBED,   metavar="MODEL")
    p.add_argument("--gen-model",   default=DEFAULT_GEN,     metavar="MODEL")
    p.add_argument("--top-k",       type=int, default=5,     metavar="N")
    p.add_argument("--no-llm",      action="store_true",     help="Skip LLM enrichment")
    p.add_argument("--force",       action="store_true",     help="Re-process even if cached")
    args = p.parse_args()

    out_dir = Path(args.output_dir)
    if not out_dir.exists():
        sys.exit(f"[!] Output directory not found: {out_dir}")

    llm = OllamaClient(
        base_url=args.ollama_url,
        embed_model=args.embed_model,
        gen_model=args.gen_model,
    )

    if args.scan_snow or args.build_index or args.query:
        llm._check()

    if args.show_snow:
        run_show_snow(out_dir)

    if args.scan_snow:
        print(f"Scanning iRules for ServiceNow ticket references …")
        run_snow_scan(out_dir, llm,
                      use_llm=not args.no_llm,
                      force=args.force)
        if not args.rebuild_html:
            print("\n[i] Run --rebuild-html to update the viewer with the new data.")

    if args.build_index:
        print(f"Building embedding index ({args.embed_model}) …")
        run_build_index(out_dir, llm, force=args.force)

    if args.query:
        run_query(args.query, out_dir, llm, top_k=args.top_k)

    if args.rebuild_html:
        run_rebuild_html(out_dir)

    if not any([args.scan_snow, args.build_index, args.query,
                args.show_snow, args.rebuild_html]):
        p.print_help()


if __name__ == "__main__":
    main()
