#!/usr/bin/env bash
# serve.sh — start the viewer + Ollama with the correct settings
set -euo pipefail

PORT=${1:-8765}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[+] Starting Ollama (OLLAMA_ORIGINS=* for browser access)…"
pkill -f "ollama serve" 2>/dev/null || true
sleep 1
OLLAMA_ORIGINS='*' /Applications/Ollama.app/Contents/Resources/ollama serve \
  &>/tmp/ollama.log & 
echo -n "    Waiting for Ollama"
for i in $(seq 1 15); do
  sleep 1; echo -n "."
  curl -s --max-time 1 http://localhost:11434/api/tags &>/dev/null && break
done
echo " ready"

echo "[+] Starting viewer at http://localhost:${PORT}/irule_viewer.html"
pkill -f "http.server ${PORT}" 2>/dev/null || true
cd "$SCRIPT_DIR/irule_output"
python3 -m http.server "$PORT" &>/tmp/irule-viewer.log &
sleep 1
cd "$SCRIPT_DIR"

echo "[+] Opening in browser…"
open "http://localhost:${PORT}/irule_viewer.html" 2>/dev/null || \
  xdg-open "http://localhost:${PORT}/irule_viewer.html" 2>/dev/null || \
  echo "    Open: http://localhost:${PORT}/irule_viewer.html"

echo ""
echo "  Viewer: http://localhost:${PORT}/irule_viewer.html"
echo "  Stop:   pkill -f 'http.server ${PORT}' && pkill -f 'ollama serve'"
