# Agent-Hunter Architecture

Last updated: 2026-04-04

This document reflects the current architecture of this repository and aligns with the active code paths in `main.py`, `api_server.py`, and `core/orchestrator.py`.

## 1. Architectural Style

Agent-Hunter is a modular monolith:

- Core runtime: Python async application centered on one orchestrator.
- Interfaces: CLI, FastAPI REST/SSE API, React dashboard, interaction modes (text/voice), Telegram bridge.
- Scanners: pluggable modules loaded from a registry.
- Intelligence: rule engine + optional Ollama helper + RL policy + long-term memory.
- Persistence: local JSON and SQLite files.

## 2. Entrypoints and Interfaces

### Runtime entrypoints

- `main.py`: primary CLI entrypoint for scanning, resume, RL diagnostics, interaction modes, and Telegram mode.
- `api_server.py`: FastAPI service used by dashboard and API clients.
- `startservers.py`: local launcher for API + dashboard (+ optional Telegram bot).

### User-facing interfaces

- CLI scanner workflow (`main.py`).
- Web dashboard (`dashboard/`) via FastAPI REST and SSE.
- Interaction loop (`interaction/`) for text/voice modes.
- Telegram bot integration (`integrations/telegram/`).

## 3. Runtime Pipeline (Actual Orchestrator Flow)

The orchestrator (`core/orchestrator.py`) executes a phased scan pipeline:

1. **Phase 0 - Pre-engagement gate**
   - Policy/checklist checks before active testing.
   - Can disable modules, enforce rate limits, or abort.

2. **Phase 1 - Recon**
   - Initial fetch + fingerprinting + WAF detection.
   - Crawl target and collect URLs/parameters.

3. **Phase 2 - Strategy**
   - Rule/AI analysis proposes module priorities.
   - RL agent re-ranks modules from learned experience.

4. **Phase 3 - Scan**
   - Adaptive module loop (RL chooses next action each step).
   - Scanner modules run with shared HTTP client and policy enforcement.
   - Reward updates, consequence analysis, and responsibility checks occur continuously.

5. **Phase 4 - Validate**
   - Finding validation and false-positive filtering.
   - PoC generation for confirmed findings.

6. **Phase 5 - Reflect**
   - Post-scan reflection writes lessons to long-term memory and target-specific memory.

7. **Finalize**
   - Episode closure, persistence writes, checkpoint cleanup on successful completion.

## 4. High-Level Component Map

### Orchestration and domain core

- `core/orchestrator.py`: lifecycle coordinator and module execution engine.
- `core/models.py`: `Scope`, `Target`, `Finding`, `ScanState`.
- `core/base_scanner.py`: common scanner abstraction/helpers.

### Intelligence and learning

- `core/Hunter_brain.py`: rule engine and optional Ollama-assisted analysis.
- `core/rl_agent.py`: RL policy and action selection.
- `core/rl_environment.py`: environment/state encoding for RL.
- `core/deep_q_backend.py`: value backend support for RL policy.
- `core/reward.py`: reward accounting and context shaping.
- `core/hunter_mind.py`: long-term cognitive memory and mistake-learning framework.

### Safety and policy

- `core/pre_engagement.py`: pre-engagement gate/checklist enforcement.
- `core/bbp_policy.py`: policy model and policy enforcer.
- `core/responsibility_engine.py`: risk-aware stopping and safety feedback.
- `core/consequence_analyzer.py`: consequence and escalation analysis.

### Execution and transport

- `utils/http_client.py`: scoped async HTTP client with concurrency/rate controls.
- `core/waf_engine.py`: WAF detection and bypass strategies.
- `core/payload_engine.py`: adaptive payload success/failure learning.
- `core/auth_session.py`: auth helper for cookies/tokens/session context.

### Recon and discovery

- `recon/crawler.py`: URL/parameter/form crawling.
- `recon/fingerprint.py`: technology/security fingerprinting.
- `recon/asset_discovery.py`: broader asset discovery (subdomains/ports/tech).

### Reporting

- `reporting/reporter.py`: report generation to Markdown, JSON, and HTML.

## 5. Scanner Architecture

Modules are registered in `core/orchestrator.py` (`SCANNER_REGISTRY`) and enabled list is maintained in `config/settings.py` (`ENABLED_MODULES`).

Current scanner groups and modules:

- `scanners/injection/`: `sql_injection`, `ssti`, `crlf_injection`, `command_injection`, `xxe_scanner`, `graphql_scanner`
- `scanners/xss/`: `xss_scanner`
- `scanners/ssrf/`: `ssrf`
- `scanners/auth/`: `auth_scanner`, `csrf_scanner`, `race_condition`
- `scanners/authz/`: `idor_scanner`
- `scanners/file/`: `path_traversal`
- `scanners/misconfig/`: `misconfig_scanner`, `host_header`
- `scanners/redirect/`: `open_redirect`
- `scanners/recon/`: `subdomain_takeover`

Total enabled scanner modules: 17.

## 6. API and Dashboard Architecture

### FastAPI service (`api_server.py`)

Primary API routes:

- Scan lifecycle:
  - `POST /api/scan`
  - `GET /api/scans`
  - `GET /api/scan/{scan_id}`
  - `GET /api/scan/{scan_id}/findings`
  - `GET /api/scan/{scan_id}/stream` (SSE)

- Runtime metadata/config:
  - `GET /api/modules`
  - `GET /api/settings`
  - `PUT /api/settings`

- Recon lifecycle:
  - `POST /api/recon`
  - `GET /api/recon/{recon_id}`
  - `GET /api/recon/{recon_id}/stream` (SSE)

API service characteristics:

- In-memory scan/recon stores with bounded scan history (`MAX_SCANS`).
- Background async tasks for scan/recon runs.
- SSE event streaming for logs, findings, phase, and completion.

### Dashboard (`dashboard/`)

- Built with React + Vite.
- Core files:
  - `dashboard/src/App.jsx`
  - `dashboard/src/api.js`
  - `dashboard/src/main.jsx`
- Uses REST for control/data and SSE for live updates.

## 7. Persistence and State Model

### File-based state

- `scan_checkpoint.json`: resume state during interrupted scans.
- `reports/scan_*.md`: markdown reports.
- `reports/scan_*.json`: structured report exports.
- `reports/scan_*.html`: HTML reports.
- `reports/rl_policy_state.json`: persisted RL policy state.
- `agent.log`: runtime logging output.

### SQLite-backed memory stores

- `data/scan_memory.db`: scan history, findings, known params, reflections.
- `data/payload_engine.db`: payload effectiveness and blocking history.
- `data/rule_engine.db`: rule engine persistence used by AI brain components.
- `data/hunter_mistakes.db`: long-term mistake/learnings/inventions memory.

## 8. Repository Structure (Current Layout)

```text
AgentiAI/
|- main.py
|- api_server.py
|- startservers.py
|- Architecture.md
|- README.md
|- CI_README.md
|- ci_local.ps1
|- requirements.txt
|- pytest.ini
|- scan_checkpoint.json
|- agent.log
|- config/
|  |- settings.py
|  |- profiles.py
|  |- ai_hunter_config.json
|  |- vulnerability_taxonomy.json
|- core/
|  |- orchestrator.py
|  |- models.py
|  |- base_scanner.py
|  |- Hunter_brain.py
|  |- hunter_mind.py
|  |- rl_agent.py
|  |- rl_environment.py
|  |- deep_q_backend.py
|  |- reward.py
|  |- memory.py
|  |- auth_session.py
|  |- waf_engine.py
|  |- payload_engine.py
|  |- pre_engagement.py
|  |- bbp_policy.py
|  |- consequence_analyzer.py
|  |- responsibility_engine.py
|- recon/
|  |- crawler.py
|  |- fingerprint.py
|  |- asset_discovery.py
|- scanners/
|  |- injection/
|  |- xss/
|  |- ssrf/
|  |- auth/
|  |- authz/
|  |- file/
|  |- misconfig/
|  |- redirect/
|  |- recon/
|- reporting/
|  |- reporter.py
|- utils/
|  |- http_client.py
|  |- console.py
|  |- health_check.py
|- interaction/
|  |- base.py
|  |- manager.py
|  |- chat.py
|  |- text_handler.py
|  |- voice_handler.py
|  |- web_research.py
|- integrations/
|  |- telegram/
|     |- bot.py
|     |- client.py
|- dashboard/
|  |- package.json
|  |- vite.config.js
|  |- eslint.config.js
|  |- index.html
|  |- src/
|- tests/
|- test-suite/
|- data/
|- reports/
|- logs/
|- manifests/
|- temp/
|- claude_code_leaked_source_code/
```

## 9. Cross-Cutting Design Decisions

1. Safety-first scanning with explicit pre-engagement policy gate.
2. Shared scoped HTTP transport for consistency across modules.
3. Rule-first strategy with AI helper and RL re-ranking.
4. Continuous learning through reward loops and persistent memory.
5. Resume support via checkpointing.
6. Real-time observability through TUI logs and SSE streams.

## 10. Extension Points

### Add a scanner module

1. Implement scanner class under an appropriate `scanners/<group>/` path.
2. Inherit `core.base_scanner.BaseScanner`.
3. Register module in `core/orchestrator.py` (`SCANNER_REGISTRY`).
4. Add module name to `config/settings.py` (`ENABLED_MODULES`).
5. Add tests under `tests/`.

### Change strategy or learning behavior

- Strategy/rule helper: `core/Hunter_brain.py`
- RL policy logic: `core/rl_agent.py`, `core/rl_environment.py`, `core/deep_q_backend.py`
- Reward shaping: `core/reward.py`

### Change policy/safety behavior

- `core/pre_engagement.py`
- `core/bbp_policy.py`
- `core/responsibility_engine.py`
- `core/consequence_analyzer.py`

### Change API or dashboard integration

- API routes and streaming: `api_server.py`
- Dashboard client and views: `dashboard/src/api.js`, `dashboard/src/App.jsx`

## 11. Quick Orientation Path for New Contributors

Read in this order for fastest architecture understanding:

1. `main.py`
2. `api_server.py`
3. `core/orchestrator.py`
4. `core/models.py`
5. `utils/http_client.py`
6. `core/Hunter_brain.py`
7. `core/rl_agent.py`
8. `recon/crawler.py` and `recon/fingerprint.py`
9. `scanners/` modules
10. `reporting/reporter.py`