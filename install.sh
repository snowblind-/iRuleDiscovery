#!/usr/bin/env bash
# install.sh — iRule Discovery full setup script
set -euo pipefail

# ── Color helpers ─────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# ── 1. Python 3.10+ check ─────────────────────────────────────────────────────
echo -e "\n${YELLOW}──────────────────────────────────────────${NC}"
echo -e "${YELLOW}  iRule Discovery — Installation${NC}"
echo -e "${YELLOW}──────────────────────────────────────────${NC}\n"

PYTHON=$(command -v python3 || true)
if [[ -z "$PYTHON" ]]; then
  err "python3 not found. Install Python 3.10+ first."
fi

PY_VER=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [[ "$PY_MAJOR" -lt 3 ]] || { [[ "$PY_MAJOR" -eq 3 ]] && [[ "$PY_MINOR" -lt 10 ]]; }; then
  err "Python 3.10+ required (found $PY_VER). Please upgrade."
fi
ok "Python $PY_VER found"

# ── 2. pip packages ───────────────────────────────────────────────────────────
echo ""
warn "Installing pip packages from requirements.txt …"
"$PYTHON" -m pip install --upgrade pip --quiet
"$PYTHON" -m pip install -r requirements.txt --quiet
ok "pip packages installed"

# ── 3. Ollama install ─────────────────────────────────────────────────────────
echo ""
if command -v ollama &>/dev/null; then
  ok "Ollama already installed ($(ollama --version 2>/dev/null || echo 'version unknown'))"
else
  warn "Installing Ollama …"
  OS="$(uname -s)"
  if [[ "$OS" == "Darwin" ]]; then
    if [[ -d "/Applications/Ollama.app" ]]; then
      ok "Ollama.app found at /Applications/Ollama.app"
    else
      err "Ollama.app not found at /Applications/Ollama.app. Download from https://ollama.com/download and place it in /Applications/, then re-run this script."
    fi
    # Launch the app so the CLI becomes available
    open /Applications/Ollama.app || true
    sleep 3
  elif [[ "$OS" == "Linux" ]]; then
    curl -fsSL https://ollama.com/install.sh | sh
    ok "Ollama installed via curl"
  else
    err "Unsupported OS: $OS. Install Ollama manually from https://ollama.com/download"
  fi
fi

# ── 4. Start Ollama serve ─────────────────────────────────────────────────────
echo ""
warn "Starting Ollama serve …"
if curl -s --max-time 2 http://localhost:11434/api/tags &>/dev/null; then
  ok "Ollama already running"
else
  ollama serve &>/tmp/ollama-serve.log &
  OLLAMA_PID=$!
  echo -n "  Waiting for Ollama to become ready"
  for i in $(seq 1 20); do
    sleep 1
    echo -n "."
    if curl -s --max-time 1 http://localhost:11434/api/tags &>/dev/null; then
      echo ""
      ok "Ollama serve is up (pid $OLLAMA_PID)"
      break
    fi
    if [[ $i -eq 20 ]]; then
      echo ""
      err "Ollama did not start in time. Check /tmp/ollama-serve.log"
    fi
  done
fi

# ── 5. Pull models ────────────────────────────────────────────────────────────
echo ""
warn "Pulling llama3 model (this may take a while on first run) …"
ollama pull llama3
ok "llama3 model ready"

echo ""
warn "Pulling nomic-embed-text model …"
ollama pull nomic-embed-text
ok "nomic-embed-text model ready"

# ── 6. Playwright chromium ────────────────────────────────────────────────────
echo ""
warn "Installing Playwright chromium …"
"$PYTHON" -m playwright install chromium
ok "Playwright chromium installed"

# ── 7. generate_demo.py ───────────────────────────────────────────────────────
echo ""
warn "Running generate_demo.py …"
"$PYTHON" generate_demo.py
ok "generate_demo.py complete"

# ── 8. irule_rag.py --scan-snow --build-index ─────────────────────────────────
echo ""
warn "Running irule_rag.py --scan-snow --build-index …"
"$PYTHON" irule_rag.py --scan-snow --build-index
ok "Scan + index complete"

# ── 9. irule_rag.py --rebuild-html ───────────────────────────────────────────
echo ""
warn "Running irule_rag.py --rebuild-html …"
"$PYTHON" irule_rag.py --rebuild-html
ok "Viewer rebuilt"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}  Installation complete!${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "  Open the viewer with:"
echo -e "  ${YELLOW}open irule_output/irule_viewer.html${NC}"
echo ""

# Make self executable
chmod +x "$0"
