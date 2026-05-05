#!/usr/bin/env bash
# Run from the repo root:  bash commit.sh
set -e
cd "$(dirname "$0")"

git add irule_discovery.py generate_demo.py README.md .gitignore

git commit -m "feat: multi-provider AI, SNow demo seeding, README refresh

AI analysis
- Add Anthropic and OpenAI backends (_analyze_with_anthropic, _analyze_with_openai)
- Add separate _XC_ANALYSIS_PROMPT (plain-question for XC RAG) vs
  _ANALYSIS_PROMPT (structured markdown for Anthropic/OpenAI)
- Reduce _XC_AI_RATE_LIMIT 20->5s; CLI --rate-limit default 20->5
- Add --ai-provider / --ai-model / --ai-key CLI flags
- Wire AI re-analysis into --rebuild-html path

Viewer
- Remove Ollama/RAG UI elements; search bar retains fast text filter
- AI label shows 'AI Assistant' when provider/model are None

Demo generator
- Add SERVICENOW_REFS with synthetic ticket data matching iRule comments
- Seed servicenow_refs table before build_html (SNow flyout works OOTB)
- provider/model set to None in demo ai_analysis entries

Bug fixes
- Replace all datetime.utcnow() with timezone-aware equivalent (Py 3.12)

README
- Reflect all screenshots in docs/ (force_graph, force_selected,
  sankey_filtered, snow_panel now referenced)
- Add RAG query section with three real CVE query examples and full
  terminal output from actual runs"

git push origin main
echo ""
echo "Pushed to github.com/snowblind-/iRuleDiscovery"
