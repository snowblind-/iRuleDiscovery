# BIG-IP iRule Discovery

A Python CLI tool that connects to one or more F5 BIG-IP devices, discovers every iRule attached to a virtual server, saves the source as `.tcl` files, and generates a fully self-contained HTML viewer with interactive diagrams, execution statistics, and AI-powered code analysis.

---

## Features

- **Multi-device discovery** — poll any number of BIG-IP hosts in a single run
- **Self-contained HTML viewer** — one portable file with no external dependencies at runtime
- **Device Fleet view** — compact tile grid showing rolled-up health status across all devices, scales cleanly to 1 000+ hosts
- **Force Graph** — D3.js force-directed graph linking devices → virtual servers → iRules; click any node to view source and stats
- **Sankey Flow diagram** — flow diagram showing which virtual servers consume which iRules
- **Execution statistics** — per-iRule execution, failure, and abort counters collected from BIG-IP on every run and stored in SQLite; hover over a node to see a sparkline of execution rate over time
- **iRule status flags** — each iRule is automatically classified:
  - 🔴 **Error** — one or more failures or aborts recorded
  - 🟡 **Orphan** — exists on BIG-IP but not attached to any virtual server
  - 🟢 **Active** — attached and has recorded executions
  - 🔵 **Attached** — attached but no executions yet
- **AI code analysis** — submits each iRule to an AI assistant for objective, function-focused review covering logic correctness, TCL best practices, performance, security, and resilience. Supports Anthropic Claude, OpenAI, and F5 Distributed Cloud AI endpoints. Results are cached by content hash so unchanged iRules are never re-analysed
- **Duplicate detection** — iRules with identical source are linked in the viewer
- **Incremental runs** — only new or changed iRules trigger discovery; unchanged files and analyses are skipped
- **Optional orphan discovery** — `--include-orphans` adds iRules that exist on the device but are not attached to any VS (system built-ins are excluded automatically)

---

## Screenshots

### Device Fleet
The landing view. Every BIG-IP host is represented as a tile coloured by its rolled-up iRule status. Filter by status, search by hostname, or sort by severity, name, or rule count. Click any tile to jump to that device in the Force Graph.

![Device Fleet](docs/screenshot_fleet.png)

### Force Graph
Interactive D3 force-directed graph. Devices (purple), virtual servers (teal), and iRules (green/yellow/red/blue by status) are linked by their configuration relationships. Scroll to zoom, drag to pan, click an iRule node to open its source in the right-hand panel.

![Force Graph](docs/screenshot_force_graph.png)

### iRule Source & AI Analysis
Clicking an iRule node opens its TCL source code. If AI analysis has been run, the panel below shows a structured review covering objective, execution flow, and actionable recommendations for improving the iRule as BIG-IP TCL code.

![iRule Source and AI Analysis](docs/screenshot_ai_analysis.png)

### ServiceNow References
If `irule_rag.py --scan-snow` has been run, any ServiceNow ticket numbers (INC, CHG, RITM, PRB, TASK, …) found in the iRule's comments or code are displayed in a dedicated panel below the AI Analysis. Each ticket shows its type badge, LLM-generated summary of what the change relates to, and the original code context. Configure `SNOW_INSTANCE_URL` in the viewer to make ticket numbers clickable links directly into your ServiceNow instance.

![ServiceNow References Panel](docs/screenshot_snow_panel.png)

### Sankey Flow
Flow diagram mapping devices → virtual servers → iRules. Node width is proportional to the number of connections. Useful for identifying heavily shared iRules and VS dependency structure.

![Sankey Flow](docs/screenshot_sankey.png)

---

## Quick Start

```bash
# Clone and install dependencies (stdlib only — no pip install required)
git clone https://github.com/snowblind-/iRuleDiscovery.git
cd iRuleDiscovery
cp .env.template .env          # fill in credentials (see Configuration)

# Discover iRules from a single BIG-IP
python3 irule_discovery.py --host 10.1.1.1 -u admin -p secret

# Multiple devices from a file
python3 irule_discovery.py --hosts-file devices.txt -u admin -p secret

# Open the viewer
open irule_output/irule_viewer.html
```

### Generate the demo viewer (no BIG-IP required)

```bash
python3 generate_demo.py
open irule_output/irule_viewer.html
```

---

## Configuration

Copy `.env.template` to `.env` and fill in your values. The `.env` file is git-ignored.

```ini
# Anthropic Claude (recommended)
ANTHROPIC_API_KEY=sk-ant-...
AI_PROVIDER=anthropic
AI_MODEL=claude-sonnet-4-6

# OpenAI
OPENAI_API_KEY=sk-...
AI_PROVIDER=openai
AI_MODEL=gpt-4o

# F5 Distributed Cloud AI
F5_XC_API_KEY=your_token
AI_PROVIDER=xc
```

Credentials can also be passed directly as CLI flags — run `python3 irule_discovery.py --help` for the full list.

---

## CLI Reference

```
python3 irule_discovery.py [OPTIONS]

Source (mutually exclusive):
  --host HOST           Single BIG-IP hostname or IP
  --hosts-file FILE     Text file, one host per line (# comments ok)

Authentication:
  -u, --username        BIG-IP username
  -p, --password        BIG-IP password

Discovery options:
  --partition NAME      Limit to one partition (default: all)
  --include-orphans     Also discover iRules not attached to any VS
  --stats-only          Refresh execution stats only, no re-discovery

AI analysis:
  --ai-provider         xc | anthropic | openai  (env: AI_PROVIDER)
  --ai-model            Model name override       (env: AI_MODEL)
  --ai-key              API key                   (env: AI_API_KEY)

Output:
  -o, --output-dir      Output directory (default: irule_output)
  --no-html             Skip viewer generation
  --rebuild-html        Re-generate viewer from existing manifest (no BIG-IP needed)

Utility:
  --stats-only          Poll execution stats without full re-discovery
  --debug               Enable debug logging
```

---

## Output

| File | Description |
|------|-------------|
| `irule_output/irule_viewer.html` | Self-contained interactive viewer |
| `irule_output/manifest.json` | Full discovery manifest (JSON) |
| `irule_output/*.tcl` | Raw iRule source files |
| `irule_output/irule_discovery.db` | SQLite database — upload registry, AI cache, stats history |

### SQLite tables

| Table | Contents |
|-------|----------|
| `upload_registry` | One row per unique iRule content hash — tracks XC library uploads |
| `ai_cache` | AI analysis results keyed by `content_hash::provider::model` |
| `irule_stats` | Time-series execution stats — one row per poll per iRule |

To force re-analysis of all iRules (e.g. after updating the AI prompt):
```bash
sqlite3 irule_output/irule_discovery.db "DELETE FROM ai_cache;"
```

---

## AI Analysis

The AI analysis is purely advisory — it reviews each iRule **as BIG-IP TCL code** and produces three sections:

1. **Objective** — what the iRule does
2. **Execution Flow** — which events fire, in what order, and what each step does
3. **Recommendations** — specific, actionable suggestions for logic correctness, TCL best practices, performance, security, and resilience

Analysis results are cached by SHA-256 content hash. An iRule that has not changed since the last run will never be re-submitted to the AI, regardless of how many times the tool is run.

---

## Local RAG & ServiceNow Scanner (`irule_rag.py`)

`irule_rag.py` uses a locally running [Ollama](https://ollama.com) instance with **Llama 3** (generation) and **nomic-embed-text** (embeddings) to extend iRule Discovery with two capabilities:

### ServiceNow ticket detection

Scans every iRule for ticket references (INC, CHG, RITM, PRB, TASK, SCTASK, …), uses the local LLM to summarise what each ticket relates to in context, and caches results in the SQLite database. The viewer displays them below the AI Analysis panel for each iRule.

```bash
# Install Ollama and pull the required models
ollama pull llama3
ollama pull nomic-embed-text

# Scan all iRules for ServiceNow references (with LLM summaries)
python3 irule_rag.py --scan-snow

# Fast scan without LLM enrichment (regex only)
python3 irule_rag.py --scan-snow --no-llm

# Rebuild the viewer to include the new ServiceNow data
python3 irule_rag.py --rebuild-html

# Print all cached references in the terminal
python3 irule_rag.py --show-snow
```

### Semantic RAG query

Build a vector embedding index and ask natural-language questions about your iRules:

```bash
# Build (or refresh) the embedding index
python3 irule_rag.py --build-index

# Ask a question — retrieves the most relevant iRules and generates an answer
python3 irule_rag.py --query "which iRules perform JWT validation?"
python3 irule_rag.py --query "show me iRules that modify HTTP headers"
python3 irule_rag.py --query "which iRules have rate limiting logic?"
```

### ServiceNow instance links

To make ticket numbers in the viewer clickable links into your ServiceNow instance, set `SNOW_INSTANCE_URL` in the generated HTML or patch it in `irule_discovery.py`:

```javascript
// In irule_discovery.py HTML template, update this line:
const SNOW_INSTANCE_URL = 'https://yourcompany.service-now.com';
```

---

## Requirements

- Python 3.10+
- Network access to BIG-IP iControl REST API (port 443)

**Optional — AI analysis** (any one of):
- Anthropic API key (`ANTHROPIC_API_KEY`)
- OpenAI API key (`OPENAI_API_KEY`)
- F5 Distributed Cloud API key (`F5_XC_API_KEY`)

**Optional — Local RAG / ServiceNow scanner** (`irule_rag.py`):
- [Ollama](https://ollama.com) running locally with `llama3` and `nomic-embed-text` pulled
- `pip3 install requests ollama chromadb`

No third-party Python packages are required for core discovery or viewer generation.

---

## License

MIT
