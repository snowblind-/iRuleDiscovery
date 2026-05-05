#!/usr/bin/env bash
# run_all.sh — regenerate demo, take screenshots, commit and push
set -e
cd "$(dirname "$0")"

echo "=== Step 1: Clear ai_cache and regenerate demo viewer ==="
sqlite3 irule_output/irule_discovery.db "DELETE FROM ai_cache;" 2>/dev/null || true
python3 generate_demo.py

echo ""
echo "=== Step 2: Take screenshots ==="
python3 take_screenshots.py

echo ""
echo "=== Step 3: Commit and push ==="
git add irule_discovery.py generate_demo.py README.md .gitignore \
        docs/screenshot_*.png \
        take_screenshots.py retake_ai_screenshot.py serve_demo.py commit.sh run_all.sh

git commit -m "feat: multi-provider AI, SNow demo seeding, README + screenshots refresh

AI analysis
- Add Anthropic and OpenAI backends (_analyze_with_anthropic, _analyze_with_openai)
- Add _XC_ANALYSIS_PROMPT (plain-question for XC RAG) separate from
  _ANALYSIS_PROMPT (structured markdown for Anthropic/OpenAI)
- Reduce _XC_AI_RATE_LIMIT 20->5s; CLI --rate-limit default 20->5
- Add --ai-provider / --ai-model / --ai-key CLI flags
- Wire AI re-analysis into --rebuild-html path

Viewer
- Remove Ollama/RAG UI elements (AI button, Ollama dot, semantic search)
- Search bar retains fast text/stem filter across all three views
- AI label shows 'AI Assistant' when provider/model are None (demo)

Demo generator
- Add SERVICENOW_REFS with synthetic ticket data matching iRule comments
- Seed servicenow_refs table before build_html (SNow flyout works OOTB)
- Clear ai_cache on each demo run so real-provider results don't pollute
- provider/model set to None in demo ai_analysis entries

Bug fixes
- Replace all datetime.utcnow() with timezone-aware equivalent (Py 3.12)

README + screenshots
- All 10 docs/screenshot_*.png regenerated from current viewer build
- No AI button, no Ollama dot, AI label shows 'AI Assistant' (demo)
- README reflects multi-provider AI, simplified install, SNow demo seeding
- Local RAG section expanded with three real CVE query examples"

git push origin main

echo ""
echo "Done! Pushed to github.com/snowblind-/iRuleDiscovery"
