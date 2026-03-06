# 🔍 AgentiAI — Autonomous Bug Bounty Agent

An AI-powered, fully autonomous vulnerability scanning agent built from scratch in Python.
Uses **Ollama** (local LLM, default `llama3:8b`) as the reasoning engine for scan strategy, finding validation, and report generation — with a self-improving rule engine as offline fallback.

---

## Table of Contents

1. [Architecture](#1-architecture)
   - [High-Level Overview](#11-high-level-overview)
   - [Data Flow](#12-data-flow)
   - [Directory Structure](#13-directory-structure)
   - [Core Data Models](#14-core-data-models)
2. [Scan Methodology — The 6-Phase Pipeline](#2-scan-methodology--the-6-phase-pipeline)
   - [Phase 0 — Pre-Engagement Gate](#phase-0--pre-engagement-gate)
   - [Phase 1 — Reconnaissance](#phase-1--reconnaissance)
   - [Phase 2 — AI-Driven Strategy](#phase-2--ai-driven-strategy)
   - [Phase 3 — Parallel Scanning](#phase-3--parallel-scanning)
   - [Phase 4 — AI Validation](#phase-4--ai-validation)
   - [Phase 5 — Reporting](#phase-5--reporting)
3. [System Components — Deep Dive](#3-system-components--deep-dive)
   - [AI Brain — Hybrid Intelligence](#31-ai-brain--hybrid-intelligence)
   - [Reward Engine](#32-reward-engine)
   - [Scan Memory](#33-scan-memory)
   - [WAF Detection & Bypass Engine](#34-waf-detection--bypass-engine)
   - [Adaptive Payload Engine](#35-adaptive-payload-engine)
   - [BBP Policy Engine](#36-bbp-policy-engine)
   - [Authenticated Scanning](#37-authenticated-scanning)
   - [HTTP Client Infrastructure](#38-http-client-infrastructure)
   - [BaseScanner Framework](#39-basescanner-framework)
4. [Scanner Modules — In-Depth Documentation](#4-scanner-modules--in-depth-documentation)
   - [4.1 SQL Injection Scanner](#41-sql-injection-scanner)
   - [4.2 SSTI Scanner](#42-ssti-scanner)
   - [4.3 CRLF Injection Scanner](#43-crlf-injection-scanner)
   - [4.4 Command Injection Scanner](#44-command-injection-scanner)
   - [4.5 XXE Scanner](#45-xxe-scanner)
   - [4.6 GraphQL Scanner](#46-graphql-scanner)
   - [4.7 XSS Scanner](#47-xss-scanner)
   - [4.8 SSRF Scanner](#48-ssrf-scanner)
   - [4.9 Auth Scanner](#49-auth-scanner)
   - [4.10 CSRF Scanner](#410-csrf-scanner)
   - [4.11 Race Condition Scanner](#411-race-condition-scanner)
   - [4.12 IDOR Scanner](#412-idor-scanner)
   - [4.13 Path Traversal Scanner](#413-path-traversal-scanner)
   - [4.14 Misconfiguration Scanner](#414-misconfiguration-scanner)
   - [4.15 Host Header Scanner](#415-host-header-scanner)
   - [4.16 Open Redirect Scanner](#416-open-redirect-scanner)
   - [4.17 Subdomain Takeover Scanner](#417-subdomain-takeover-scanner)
5. [Reconnaissance Subsystem](#5-reconnaissance-subsystem)
   - [Crawler](#51-crawler)
   - [Fingerprinter](#52-fingerprinter)
6. [Reporting Subsystem](#6-reporting-subsystem)
7. [Quick Start](#7-quick-start)
8. [CLI Reference](#8-cli-reference)
9. [Configuration](#9-configuration)
10. [Adding New Scanners](#10-adding-new-scanners)
11. [Legal Notice](#11-legal-notice)

---

# 1. Architecture

## 1.1 High-Level Overview

```
┌──────────────────────────────────────────────────────────────────────┐
│                          main.py (CLI)                               │
│   argparse → Target + Scope + Policy → Orchestrator                  │
└────────────────────────────┬─────────────────────────────────────────┘
                             │
┌────────────────────────────▼─────────────────────────────────────────┐
│                    Orchestrator (core/orchestrator.py)                │
│                                                                      │
│  6-Phase Pipeline:                                                   │
│  ┌─────────┐ ┌───────┐ ┌──────────┐ ┌──────┐ ┌──────────┐ ┌──────┐ │
│  │Phase 0  │→│Phase 1│→│ Phase 2  │→│Phase3│→│ Phase 4  │→│Phase5│ │
│  │Pre-Gate │ │ Recon │ │ Strategy │ │ Scan │ │ Validate │ │Report│ │
│  └─────────┘ └───────┘ └──────────┘ └──────┘ └──────────┘ └──────┘ │
│                                                                      │
│  Cross-cutting systems:                                              │
│  ┌─────────┐ ┌────────┐ ┌──────────┐ ┌────────┐ ┌───────────────┐  │
│  │AI Brain │ │Reward  │ │  Memory  │ │  WAF   │ │Payload Engine │  │
│  │(Ollama) │ │Engine  │ │ (SQLite) │ │ Engine │ │  (Adaptive)   │  │
│  └─────────┘ └────────┘ └──────────┘ └────────┘ └───────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
                             │
        ┌────────────────────┼───────────────────┐
        │                    │                   │
┌───────▼───────┐ ┌──────────▼──────┐ ┌──────────▼──────┐
│   HttpClient  │ │  17 Scanners    │ │   Reporter       │
│  (scope-aware │ │  (async, plugin │ │ (Markdown, JSON, │
│   rate-limit) │ │   architecture) │ │  HTML, HackerOne)│
└───────────────┘ └─────────────────┘ └──────────────────┘
```

## 1.2 Data Flow

```
CLI Input (--target, --scope, --policy, --modules)
    │
    ▼
┌────────────┐     ┌──────────────┐
│  Target    │────▶│ Scope Model  │  Domain allow/deny lists, path exclusions
│  Model     │     └──────────────┘
└─────┬──────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│                   Orchestrator.run()                 │
│                                                     │
│  Phase 0: BBPPolicy ──▶ PreEngagementGate           │
│      │            checks scope, legal risk,         │
│      │            disables modules, sets rate limit  │
│      ▼                                              │
│  Phase 1: Fingerprinter ──▶ WAFEngine.detect()      │
│      │    Crawler.crawl()                           │
│      │    Populates: technologies, discovered_urls, │
│      │               discovered_params, js_files    │
│      ▼                                              │
│  Phase 2: AIBrain.analyse_recon()                   │
│      │    Ollama prompt ──▶ JSON: priority_modules  │
│      │    RuleEngine fallback (TECH_VULN_MAP)       │
│      │    Merges AI + rule priorities               │
│      ▼                                              │
│  Phase 3: asyncio.gather(scanner1, scanner2, ...)   │
│      │    Semaphore(3) limits concurrency            │
│      │    Each scanner: run(ScanState) → [Finding]  │
│      │    RewardEngine.score_scanner_results()      │
│      │    PayloadEngine.record_result()             │
│      ▼                                              │
│  Phase 4: AIBrain.validate_finding() per finding    │
│      │    PolicyEnforcer.filter_findings()           │
│      │    AI: is_true_positive, confidence, severity│
│      │    AI: generate_poc() for confirmed          │
│      ▼                                              │
│  Phase 5: Reporter.generate_markdown/json/html()    │
│           AIBrain.summarise_scan()                   │
│           Memory.store_findings()                    │
└─────────────────────────────────────────────────────┘
      │
      ▼
   reports/scan_<host>_<timestamp>.{md,json,html}
```

## 1.3 Directory Structure

```
AgentiAI/
├── main.py                         # CLI entry point (argparse, async main loop)
├── config/
│   ├── settings.py                 # Config-driven settings (env + JSON file)
│   ├── ai_hunter_config.json       # Master config (Ollama, H1, health checks)
│   ├── profiles.py                 # Saved scope profiles (per-target presets)
│   └── vulnerability_taxonomy.json # CWE/CVSS taxonomy reference
│
├── core/
│   ├── orchestrator.py             # Main 6-phase pipeline + checkpoint/resume
│   ├── ai_brain.py                 # Hybrid AI: OllamaClient + RuleEngine + AIBrain
│   ├── base_scanner.py             # Abstract scanner base: test_payload, make_finding
│   ├── models.py                   # Finding, ScanState, Target, Scope dataclasses
│   ├── reward.py                   # RL reward engine for action scoring
│   ├── memory.py                   # SQLite-backed cross-scan intelligence
│   ├── waf_engine.py               # WAF detection (10 WAFs) + bypass techniques
│   ├── payload_engine.py           # Adaptive payload selection (learns history)
│   ├── auth_session.py             # Authenticated scanning (form, bearer, API key)
│   ├── bbp_policy.py               # Bug bounty policy enforcement + PolicyEnforcer
│   └── pre_engagement.py           # Safety gate checklist (PreEngagementGate)
│
├── scanners/                       # 17 scanner modules across 8 categories
│   ├── injection/                  #   sql_injection, ssti, crlf, command, xxe, graphql
│   ├── xss/                        #   Reflected, Stored, DOM XSS
│   ├── ssrf/                       #   SSRF + cloud metadata
│   ├── auth/                       #   JWT, CSRF, Race Conditions
│   ├── authz/                      #   IDOR / BOLA
│   ├── file/                       #   Path Traversal / LFI
│   ├── misconfig/                  #   Exposed files, CORS, Host Header, sec headers
│   ├── redirect/                   #   Open Redirect
│   └── recon/                      #   Subdomain Takeover
│
├── recon/
│   ├── crawler.py                  # Async BFS crawler + JS analysis + secret detection
│   └── fingerprint.py              # Tech fingerprinting (headers, body, cookies)
│
├── reporting/
│   ├── reporter.py                 # Markdown, JSON, HTML report generation
│   ├── hackerone_report.py         # HackerOne-formatted report builder
│   └── hackerone_api.py            # HackerOne API client (submit reports)
│
├── utils/
│   ├── http_client.py              # Async httpx: scope enforcement, rate limit, retry
│   ├── console.py                  # Rich TUI live dashboard (phases, findings, score)
│   └── health_check.py             # Config-driven health check utility
│
├── data/                           # SQLite DBs (scan_memory.db, payload_engine.db, rule_engine.db)
└── reports/                        # Generated scan reports (.md, .json, .html)
```

## 1.4 Core Data Models

All data models are defined in `core/models.py` as Python dataclasses.

### `Scope`

Controls what the agent is allowed to access:

| Field | Type | Purpose |
|-------|------|---------|
| `allowed_domains` | `List[str]` | Wildcard-supported domain patterns (e.g., `*.example.com`) |
| `allowed_urls` | `List[str]` | Specific URL patterns |
| `excluded_domains` | `List[str]` | Blacklisted domains |
| `excluded_paths` | `List[str]` | Blacklisted URL paths |

The `is_in_scope(url)` method uses regex matching: `*` in patterns maps to `.*` for flexible wildcard matching.

### `Target`

Represents the scan target and all intelligence gathered during recon:

| Field | Type | Purpose |
|-------|------|---------|
| `url` | `str` | Root target URL |
| `scope` | `Scope` | Access control boundary |
| `technologies` | `List[str]` | Detected tech stack (PHP, Nginx, React, etc.) |
| `discovered_urls` | `List[str]` | All URLs found during crawling |
| `discovered_params` | `Dict[str, List[str]]` | URL → parameter names mapping |
| `metadata` | `Dict` | Extra data: `js_files`, `secrets_in_js`, `waf`, fingerprint data |
| `headers` | `Dict[str, str]` | Response headers from initial request |
| `cookies` | `Dict[str, str]` | Session cookies |

### `Finding`

A single discovered vulnerability:

| Field | Type | Purpose |
|-------|------|---------|
| `title` | `str` | Human-readable vulnerability title |
| `vuln_type` | `str` | Machine ID (e.g., `sql_injection_error`, `reflected_xss`) |
| `severity` | `str` | `critical` / `high` / `medium` / `low` / `info` |
| `url` | `str` | Affected URL |
| `parameter` | `str` | Vulnerable parameter name |
| `method` | `str` | HTTP method used (`GET`, `POST`, etc.) |
| `payload` | `str` | Exact payload that triggered the vulnerability |
| `evidence` | `str` | Proof of exploitation (DB error, file content, etc.) |
| `request` | `str` | Raw HTTP request that caused the finding |
| `response` | `str` | Relevant response excerpt |
| `poc_steps` | `List[str]` | Step-by-step reproduction instructions |
| `cwe_id` | `str` | CWE identifier (e.g., `CWE-89`) |
| `owasp_category` | `str` | OWASP 2021 mapping (e.g., `A03:2021 - Injection`) |
| `confirmed` | `bool` | Whether AI/rule engine confirmed the finding |
| `false_positive` | `bool` | Whether AI flagged as false positive |
| `ai_analysis` | `str` | AI reasoning for confirmation/rejection |
| `remediation` | `str` | AI-generated fix guidance |
| `module` | `str` | Scanner module that produced this finding |

### `ScanState`

The mutable state object that flows through all 6 phases:

| Field | Type | Purpose |
|-------|------|---------|
| `target` | `Target` | The scan target with accumulated recon data |
| `phase` | `str` | Current pipeline phase (`init`, `recon`, `strategy`, `scan`, `validate`, `complete`) |
| `findings` | `List[Finding]` | Accumulated vulnerability findings |
| `modules_run` | `List[str]` | Scanners that have completed |
| `modules_pending` | `List[str]` | Scanners queued (ordered by priority) |
| `agent_thoughts` | `List[str]` | Timestamped reasoning log |
| `errors` | `List[str]` | Errors encountered during scanning |

Deduplication: `add_finding()` prevents duplicate findings using the key `(url, parameter, vuln_type, payload)`.

---

# 2. Scan Methodology — The 6-Phase Pipeline

The orchestrator (`core/orchestrator.py`) implements a structured pipeline inspired by professional penetration testing methodology. Each phase builds on the previous one, and scan state is checkpointed after each phase for resume capability.

## Phase 0 — Pre-Engagement Gate

**Purpose:** Ensure the scan is legally authorized and compliant with bug bounty program rules before any network traffic is generated.

**Process:**

```
                    ┌──────────────────────────┐
                    │  Is BBP Policy provided? │
                    └────────┬─────────────────┘
                      yes    │     no
               ┌─────────────▼──┐    │
               │PolicyEnforcer  │    ▼
               │.pre_scan_check │  Basic scope check + proceed
               └────────┬──────┘
                        ▼
        ┌──────────────────────────────┐
        │  PreEngagementGate.run_checks│
        │  1. Target in scope?         │──── NO → ABORT
        │  2. Vuln types excluded?     │──── Filter modules
        │  3. Mass scan banned?        │──── Disable aggressive modules
        │  4. Safe harbor present?     │──── Flag legal risk level
        │  5. Rate limit specified?    │──── Enforce on HttpClient
        └──────────────┬───────────────┘
                       ▼
          ┌──────────────────────┐
          │ Interactive Prompt   │
          │ "Proceed? [y/N]"    │──── N → ABORT
          │ (skip with --yes)    │
          └──────────┬───────────┘
                     ▼
               SCAN PROCEEDS
```

**Enforcement actions:**
- **Scope violation** → scan aborted, no requests made
- **Disabled modules** → automatically removed from the scanner queue (e.g., race condition scanner disabled when `no_dos: true`)
- **Rate limit** → `HttpClient._rate_limiter._delay` set to `1/rate_limit_rps`
- **Legal risk** → displayed as LOW/MEDIUM/HIGH in the confirmation prompt
- **No safe harbor** → flagged as high legal risk, requires explicit user confirmation

## Phase 1 — Reconnaissance

**Purpose:** Gather intelligence about the target's technology stack, attack surface, and defenses.

**Process:**

```
Target URL
    │
    ├─── 1. HTTP GET → Fingerprinter.analyse()
    │         ├── Header-based detection (X-Powered-By, Server)
    │         ├── Body-based detection (wp-content, __next, graphql)
    │         ├── Cookie-based detection (PHPSESSID, JSESSIONID)
    │         └── Security header audit (HSTS, CSP, X-Frame-Options)
    │         Result: technologies[], interesting_headers{}
    │
    ├─── 2. WAFEngine.detect()
    │         ├── Baseline GET request
    │         ├── Signature scan on response headers (10 WAF fingerprints)
    │         ├── Send malicious payloads: <script>alert(1)</script>
    │         │   Analyze 403/406/503 responses + body/header signatures
    │         └── Result: detected_waf (e.g., "cloudflare", "modsecurity", null)
    │
    └─── 3. Crawler.crawl() — async BFS up to MAX_CRAWL_DEPTH
              ├── HTML parsing (BeautifulSoup): <a href>, <form>, <script src>
              ├── JS file analysis: fetch(), axios, url: "...", endpoint: "..."
              ├── Secret detection: API keys, AWS keys, Bearer tokens, GitHub PATs
              ├── Query parameter extraction: parse_qs on all URLs
              └── Result: discovered_urls[], discovered_params{}, js_files[], secrets[]
```

**Technology fingerprint database:**

| Detection Source | Technologies |
|-----------------|--------------|
| `X-Powered-By` header | PHP, ASP.NET, Express.js, Next.js |
| `Server` header | Nginx, Apache, IIS, LiteSpeed, Cloudflare, Amazon S3 |
| HTML body patterns | WordPress, Drupal, Joomla, Shopify, Magento, Laravel, Django, React, Vue.js, Angular, GraphQL, Swagger UI |
| `Set-Cookie` values | PHP (`PHPSESSID`), Java EE (`JSESSIONID`), ASP (`ASPSESSIONID`), Laravel (`laravel_session`) |

**Crawler capabilities:**
- Breadth-first async crawling with configurable depth limit
- HTML link extraction (`<a>`, `<link>`, `<script src>`)
- Form parameter discovery (input names from `<form>` tags)
- JavaScript endpoint extraction (6 regex patterns: `fetch()`, `axios`, `url:`, `endpoint:`, `api_url:`)
- Hardcoded secret detection (7 patterns: API keys, AWS credentials, bearer tokens, GitHub PATs)
- Scope-aware: skips out-of-scope URLs automatically
- Configurable max URLs per target

## Phase 2 — AI-Driven Strategy

**Purpose:** Analyze reconnaissance results to create an intelligent, prioritized scan plan.

**Process:**

```
         ┌───────────────────────────────────┐
         │  Input: Target (technologies,     │
         │  URLs, params, WAF, headers)       │
         │  + Reward Engine context            │
         │  + Scan Memory context (past scans)│
         └──────────┬────────────────────────┘
                    │
          ┌─────────▼──────────┐
          │  Ollama available?  │
          └──┬──────────┬──────┘
          yes│          │no
             ▼          ▼
     ┌────────────┐  ┌──────────────────────────────────┐
     │ LLM Prompt:│  │ Rule Engine (TECH_VULN_MAP):      │
     │ Technologies│  │ PHP → [sqli, lfi, ssti, misconfig]│
     │ URLs, params│  │ Express.js → [ssti, ssrf, xss]   │
     │ WAF, reward │  │ + Learned strategies from DB      │
     │ history     │  │ + Parameter heuristics:            │
     │  ↓          │  │   id/uid → IDOR; url/redirect →   │
     │ JSON output:│  │   SSRF + Open Redirect; file/     │
     │ priority_   │  │   path → LFI; admin/login → Auth  │
     │ modules[]   │  │ + Endpoint heuristics:             │
     └──────┬─────┘  │   api/graphql → IDOR               │
            │        └──────────────┬───────────────────────┘
            │                       │
            ▼                       ▼
     ┌──────────────────────────────────────┐
     │ Merge: AI modules first, then rule   │
     │ engine extras that AI missed.         │
     │ Result: ordered modules_pending[]    │
     └──────────────────────────────────────┘
```

**Technology → Scanner priority map (rule engine):**

| Tech Stack | Priority Scanners |
|-----------|------------------|
| PHP | `sql_injection`, `path_traversal`, `ssti`, `misconfig_scanner`, `xss_scanner` |
| WordPress | `sql_injection`, `xss_scanner`, `auth_scanner`, `misconfig_scanner`, `path_traversal` |
| Laravel | `sql_injection`, `ssti`, `misconfig_scanner`, `auth_scanner`, `path_traversal` |
| Django | `ssti`, `sql_injection`, `misconfig_scanner`, `auth_scanner`, `idor_scanner` |
| Express.js | `ssti`, `ssrf`, `xss_scanner`, `idor_scanner`, `auth_scanner` |
| Next.js | `ssrf`, `xss_scanner`, `auth_scanner`, `misconfig_scanner`, `open_redirect` |
| React | `xss_scanner`, `auth_scanner`, `idor_scanner`, `open_redirect` |
| Java EE | `sql_injection`, `ssti`, `ssrf`, `path_traversal`, `misconfig_scanner` |
| Ruby on Rails | `sql_injection`, `ssti`, `auth_scanner`, `idor_scanner`, `misconfig_scanner` |
| GraphQL | `sql_injection`, `idor_scanner`, `auth_scanner`, `ssrf` |

**Adaptive learning:** Every scan result feeds back into the rule engine's SQLite database. If SSTI consistently finds vulnerabilities on Laravel targets, its priority increases for future Laravel scans.

## Phase 3 — Parallel Scanning

**Purpose:** Execute all scanner modules concurrently against the target.

**Process:**

```
     modules_pending: [sql_injection, xss_scanner, ssrf, ...]
                │
                ▼
     ┌──────────────────────────────────────────────────────┐
     │  asyncio.gather(*[run_one(name, cls) for each])      │
     │                                                      │
     │  Concurrency control: asyncio.Semaphore(3)           │
     │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐    │
     │  │ Scanner A    │ │ Scanner B    │ │ Scanner C    │   │
     │  │ sql_injection│ │ xss_scanner  │ │ ssrf         │   │
     │  │              │ │              │ │              │    │
     │  │ 1. setup()   │ │ 1. setup()   │ │ 1. setup()   │   │
     │  │ 2. run(state)│ │ 2. run(state)│ │ 2. run(state)│   │
     │  │ 3. teardown()│ │ 3. teardown()│ │ 3. teardown()│   │
     │  │ → [Finding]  │ │ → [Finding]  │ │ → [Finding]  │   │
     │  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘   │
     │         │                │                │            │
     │         ▼                ▼                ▼            │
     │  RewardEngine.score_scanner_results() per module       │
     │  AIBrain.learn_scan_results() → update rule DB         │
     │  TUI: add_finding(), complete_module()                 │
     └──────────────────────┬───────────────────────────────┘
                            │
                 state.findings += all results
                 Dedup: (url, param, vuln_type, payload)
```

**Per-scanner execution wrapper (`run_one`):**
1. Acquires semaphore (max 3 concurrent)
2. Instantiates scanner with shared `HttpClient`
3. Calls `scanner.setup()` → `scanner.run(state)` → `scanner.teardown()`
4. Wraps `run()` in `asyncio.wait_for(timeout=SCAN_TIMEOUT_PER_MODULE)` — default 120s
5. On timeout: logs error, records `no_progress_action` penalty
6. On exception: logs error, records `incorrect_exploit_attempt` penalty
7. On success: scores findings with RewardEngine, feeds results back to RuleEngine

## Phase 4 — AI Validation

**Purpose:** Eliminate false positives, confirm true vulnerabilities, generate PoC steps, and calibrate severity.

**Process:**

```
     state.findings (raw)
           │
           ▼
     ┌──── Policy Filter ────┐
     │ Remove findings whose  │
     │ vuln_type is in        │
     │ oos_vuln_types[]       │
     └────────┬───────────────┘
              │
     For each finding:
              │
     ┌────────▼──────────────────────────────────────────────────┐
     │  Rule Engine Validation (always runs first):              │
     │  VALIDATION_RULES[vuln_type]:                             │
     │    base_confidence: 50-100%                               │
     │    confirmed_if: lambda checking evidence patterns        │
     │    Example:                                                │
     │      sql_injection_error: conf=85%, check for DB keywords │
     │      reflected_xss: conf=80%, check for <script/payload   │
     │      ssrf_cloud_metadata: conf=90%, check for ami-id      │
     │      missing_security_header: conf=100%, always true      │
     │      idor: conf=55%, check for "vs" in payload            │
     └────────┬──────────────────────────────────────────────────┘
              │
     ┌────────▼──────────────────────┐
     │  Ollama Enhancement           │
     │  (if available):              │
     │                               │
     │  Prompt: vuln_type, URL,      │
     │  param, payload, evidence     │
     │  → JSON: is_true_positive,    │
     │    confidence, severity,      │
     │    remediation                │
     │                               │
     │  Learns: ai_outputs table     │
     └────────┬──────────────────────┘
              │
     ┌────────▼──────────────────────┐
     │  PoC Generation               │
     │  (for confirmed findings):    │
     │                               │
     │  Rule engine: template-based  │
     │  Ollama: context-aware steps  │
     └────────┬──────────────────────┘
              │
              ▼
     state.findings = validated (FPs removed)
     RewardEngine: +1.0 for confirmed, -1.0 for FP
```

**Validation confidence by vulnerability type:**

| Vuln Type | Base Confidence | Confirmation Rule |
|-----------|----------------|-------------------|
| `sql_injection_error` | 85% | Evidence contains SQL/DB keywords |
| `sql_injection_time_based` | 70% | Evidence mentions "delayed" or payload has "sleep" |
| `sql_injection_blind_boolean` | 60% | Evidence contains "true len" |
| `reflected_xss` | 80% | Evidence says "reflected" or payload has `<script` |
| `dom_xss` | 50% | Evidence contains `innerHTML`, `eval(`, `document.write` |
| `ssrf_cloud_metadata` | 90% | Evidence contains cloud metadata identifiers |
| `ssti` | 85% | Evidence says "evaluated" and contains computed result |
| `jwt_alg_none` | 90% | Title mentions "alg:none" and HTTP 200 in evidence |
| `default_credentials` | 95% | Evidence says "login succeeded" |
| `path_traversal` | 85% | Evidence contains `root:x:0` or boot loader |
| `sensitive_file_exposure` | 80% | Evidence contains "http 200" |
| `subdomain_takeover` | 65% | Evidence matches service-specific signatures |

## Phase 5 — Reporting

**Purpose:** Generate comprehensive reports in multiple formats and persist scan data.

**Output formats:**

| Format | File | Content |
|--------|------|---------|
| Markdown | `scan_<host>_<timestamp>.md` | Executive summary, stats table, severity-sorted findings with full PoC, agent reasoning log |
| JSON | `scan_<host>_<timestamp>.json` | Machine-readable: scan_id, target, statistics, findings array, modules_run, errors |
| HTML | `scan_<host>_<timestamp>.html` | Styled cards with severity-colored badges, collapsible sections, dark theme |

**Post-scan persistence:**
- `ScanMemory.store_findings()` — all findings saved to SQLite
- `ScanMemory.finish_scan()` — scan metadata + reward data persisted
- Checkpoint file removed on successful completion

---

# 3. System Components — Deep Dive

## 3.1 AI Brain — Hybrid Intelligence

**File:** `core/ai_brain.py` (852 lines)

The AI brain orchestrates three tiers of intelligence:

```
┌────────────────────────────────────────────────────┐
│                   AIBrain                          │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │  Tier 1: OllamaClient                        │  │
│  │  Primary model: llama3:8b                    │  │
│  │  Fallback model: mistral:7b                  │  │
│  │  Endpoints: /api/generate, /api/chat          │  │
│  │  Features:                                    │  │
│  │    - Auto-retry with context reduction        │  │
│  │    - Auto-pull model if not found             │  │
│  │    - Configurable temperature, top_p, top_k   │  │
│  │    - Timeout with exponential backoff         │  │
│  └──────────────────────────┬───────────────────┘  │
│                             │ fails / unavailable  │
│  ┌──────────────────────────▼───────────────────┐  │
│  │  Tier 2: RuleEngine (SQLite)                  │  │
│  │  Static rules: TECH_VULN_MAP (14 tech stacks) │  │
│  │  Static rules: VALIDATION_RULES (17 types)    │  │
│  │  Static rules: POC_TEMPLATES (5 vuln types)   │  │
│  │  Learned rules: learned_strategies table       │  │
│  │  Learned rules: learned_validations table      │  │
│  │  AI output history: ai_outputs table           │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  Learning loop: every Ollama output is stored      │
│  in the rule engine DB via learn_from_ai()         │
│  → rule engine improves over time                  │
└────────────────────────────────────────────────────┘
```

**OllamaClient retry logic:**
1. First attempt with full context window (`num_ctx` from config)
2. On timeout: halve context window and `num_predict`, retry
3. Up to `max_retries` attempts (default: 3)
4. On connection refused: log warning, return empty → triggers rule engine fallback

**Model availability check:**
1. Query `/api/tags` to list available models
2. Check primary model (`llama3:8b`) — flexible matching (prefix or contains)
3. If primary not found, try fallback (`mistral:7b`)
4. If neither found and `auto_pull` configured: pull primary model (up to 600s timeout)
5. If all fail: `_available = False`, all operations fall through to rule engine

**AIBrain unified interface:**

| Method | Ollama Behavior | Rule Engine Fallback |
|--------|----------------|---------------------|
| `analyse_recon(target)` | JSON prompt with tech/URLs/params → priority modules | `TECH_VULN_MAP` + parameter heuristics + learned strategies |
| `validate_finding(finding)` | JSON prompt with vuln details → true_positive/confidence | `VALIDATION_RULES` pattern matching + learned validations |
| `generate_poc(finding)` | JSON prompt → step-by-step array | `POC_TEMPLATES` with field substitution |
| `summarise_scan(state)` | Full prose prompt → executive summary | Template-based stats + risk assessment |
| `generate_adaptive_payloads(type, ctx)` | Prompt with tech/WAF/failed payloads → payload array | Returns `[]` (no rule engine equivalent) |

## 3.2 Reward Engine

**File:** `core/reward.py`

Reinforcement learning-style scoring that guides autonomous decision-making:

```
┌──────────────────────────────────────────────────────────┐
│                    RewardEngine                          │
│                                                          │
│  Reward Scheme (configurable via --reward-scheme):        │
│  ┌────────────────────────────────────┬────────────────┐ │
│  │ Action                             │ Reward Value   │ │
│  ├────────────────────────────────────┼────────────────┤ │
│  │ successful_exploit                 │     +1.0       │ │
│  │ root_shell_obtained               │     +2.0       │ │
│  │ correct_service_identification     │     +0.5       │ │
│  │ correct_vulnerability_mapping      │     +0.5       │ │
│  │ valid_payload_construction         │     +0.5       │ │
│  │ privilege_escalation_success       │     +1.0       │ │
│  │ incorrect_exploit_attempt          │     -1.0       │ │
│  │ crashed_service                    │     -0.5       │ │
│  │ redundant_scan                     │     -0.2       │ │
│  │ no_progress_action                 │      0.0       │ │
│  └────────────────────────────────────┴────────────────┘ │
│                                                          │
│  Scoring triggers:                                       │
│  - Recon: +0.5 for tech identification, +0.5 for URLs   │
│  - Per scanner: +1.0 per confirmed, +0.5 per unconfirmed│
│  - Redundant finding (known from memory): -0.2           │
│  - Scanner timeout: 0.0 (no progress)                    │
│  - Scanner exception: -1.0 (incorrect attempt)           │
│  - FP during validation: -1.0                            │
│                                                          │
│  Output:                                                 │
│  - to_ai_context(): formatted history for LLM prompts    │
│  - to_dict(): JSON-serializable for checkpoint/memory    │
│  - total_score: running sum displayed in TUI              │
└──────────────────────────────────────────────────────────┘
```

## 3.3 Scan Memory

**File:** `core/memory.py` — SQLite-backed persistent intelligence

**Database schema:**

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `scans` | Scan session history | `scan_id`, `target_url`, `total_findings`, `confirmed`, `total_score`, `reward_data` |
| `findings` | All findings across all scans | `finding_id`, `scan_id`, `vuln_type`, `severity`, `url`, `parameter`, `confirmed` |
| `known_params` | Parameter-level scan tracking | `url`, `parameter`, `vuln_type`, `was_vulnerable`, `last_scanned` |

**Key capabilities:**
- **Redundancy avoidance:** `get_known_findings()` returns previously discovered `(url, parameter, vuln_type)` tuples — the reward engine penalizes re-finding known issues
- **Freshness check:** `was_recently_scanned()` prevents re-scanning a parameter if it was tested within `max_age_hours`
- **Target profiling:** `get_target_profile()` aggregates all historical data about a target — total scans, known vulnerabilities, technologies, best score
- **AI context:** `to_ai_context()` formats memory as a text block for the LLM strategy prompt

## 3.4 WAF Detection & Bypass Engine

**File:** `core/waf_engine.py`

**Detection methodology:**

| Step | Method | Detail |
|------|--------|--------|
| 1 | Baseline request | Normal GET to target URL, capture response headers |
| 2 | Header fingerprinting | Match response headers against 10 WAF signature databases |
| 3 | Provocation | Send known-blocked payloads (`<script>alert(1)</script>`, `' OR 1=1--`, `../../etc/passwd`) |
| 4 | Response analysis | Check for 403/406/503 status codes + WAF-specific body/header signatures |
| 5 | Fallback | If 403 on malicious input with small body, flag as "unknown" WAF |

**Supported WAFs and their signatures:**

| WAF | Header Signatures | Body Signatures |
|-----|------------------|-----------------|
| Cloudflare | `cf-ray`, `cf-cache-status`, `__cfduid` | "cloudflare", "attention required" |
| Akamai | `x-akamai-transformed`, `akamai-grn` | "akamai", "reference#", "access denied" |
| AWS WAF | `x-amzn-requestid`, `x-amz-cf-id` | "aws", "request blocked" |
| Imperva | `x-iinfo`, `x-cdn` | "incapsula", "imperva", "visitorid" |
| F5 BIG-IP | `x-wa-info`, `bigipserver` | "the requested url was rejected" |
| ModSecurity | `mod_security`, `nyob` | "mod_security", "not acceptable" |
| Sucuri | `x-sucuri-id`, `x-sucuri-cache` | "sucuri", "cloudproxy" |
| Wordfence | — | "wordfence", "generated by wordfence" |
| FortiWeb | `fortiwafsid` | "fortigate", "fortiweb" |
| Barracuda | `barra_counter_session` | "barracuda", "barra_counter" |

**Bypass techniques:**

| Technique | Transformation | Example |
|-----------|---------------|---------|
| Case swap | `payload.swapcase()` | `SELECT` → `sELECT` |
| Double encode | `%` → `%25` | `%27` → `%2527` |
| Null byte | Prepend `%00` | `%00' OR 1=1--` |
| Unicode | `<` → `%u003c`, `>` → `%u003e` | Bypass UTF-8 filters |
| Comment split | `SELECT` → `SEL/**/ECT` | Bypass keyword detection |
| Concat | `'` → `'+'` | Break string matching |
| Newline/Tab | Space → `\n` or `\t` | Evade space-based rules |
| WAF-specific | Cloudflare: chunked transfer; ModSecurity: `/*!SELECT*/` | WAF-tuned evasion |

**Evasion headers pool:** 11 headers including `X-Forwarded-For: 127.0.0.1`, `X-Originating-IP: 127.0.0.1`, `X-Real-IP: 127.0.0.1`, `Content-Type: application/x-www-form-urlencoded; charset=ibm037`

## 3.5 Adaptive Payload Engine

**File:** `core/payload_engine.py` — SQLite-backed learning system

**Database schema:**

| Table | Purpose |
|-------|---------|
| `payload_stats` | Per-payload success/failure/blocked counts, keyed by `(payload_hash, vuln_type, tech_stack, waf)` |
| `effective_patterns` | Aggregated pattern success rates per tech stack |

**Key operations:**

| Method | Purpose |
|--------|---------|
| `record_result(payload, vuln_type, success, blocked, tech, waf)` | Track whether a payload succeeded, failed, or was WAF-blocked |
| `get_best_payloads(vuln_type, tech, waf)` | Retrieve historically effective payloads sorted by success rate |
| `get_blocked_payloads(waf)` | Get payloads known to be blocked by a specific WAF |
| `prioritize_payloads(payloads, vuln_type, tech, waf)` | Reorder: proven first → unknown → known-blocked last |
| `update_patterns(tech, vuln_type)` | Aggregate stats into effective_patterns summary |

## 3.6 BBP Policy Engine

**File:** `core/bbp_policy.py` (504 lines) — Safety-critical policy enforcement

**BBPPolicy data model:**

| Section | Fields | Purpose |
|---------|--------|---------|
| Program Info | `program_name`, `platform`, `program_url` | Identify the bug bounty program |
| In-Scope | `in_scope_domains`, `in_scope_urls`, `asset_types` | What CAN be tested |
| Out-of-Scope | `oos_domains`, `oos_urls`, `oos_paths`, `oos_ips` | What MUST NOT be tested |
| Excluded Vulns | `oos_vuln_types` | Vulnerability types not accepted (e.g., `self_xss`) |
| Restrictions | `no_dos`, `no_data_exfil`, `no_data_modification`, `no_social_engineering`, `no_automated_mass_scan` | Testing limitations |
| Rate Limiting | `rate_limit_rps` | Maximum requests per second |
| Safe Harbor | `safe_harbor`, `disclosure_policy`, `min_severity` | Legal protection and reporting rules |

**PolicyEnforcer lifecycle:**

| Stage | Check | Action on Violation |
|-------|-------|-------------------|
| Pre-scan | Target URL in scope? | ABORT |
| Pre-scan | Automated scanning banned? | Disable mass-scan modules |
| Pre-scan | Rate limit specified? | Set HttpClient delay |
| During scan | URL in scope? | Skip request |
| During scan | Vuln type excluded? | Skip scanner module |
| Post-scan | Finding vuln_type in oos_vuln_types? | Remove from results |

## 3.7 Authenticated Scanning

**File:** `core/auth_session.py` — Session management for scanning behind login walls

**Authentication methods:**

| Method | Input | Process |
|--------|-------|---------|
| Form login | URL + username + password | GET login page → extract CSRF token → POST credentials → capture session cookies |
| API bearer | URL + JSON credentials | POST credentials → extract token from JSON response → set `Authorization: Bearer <token>` |
| Manual bearer | Token string | Directly set `Authorization: Bearer <token>` header |
| Manual cookies | Cookie dict | Directly set session cookies |
| API key | Key name + value | Set custom header (e.g., `X-API-Key: value`) |

**CSRF token extraction:** Regex patterns match common token field names: `csrf_token`, `_token`, `authenticity_token`, `__RequestVerificationToken`, `csrfmiddlewaretoken`, `_csrf`, `_wpnonce`, `nonce`.

**Auth headers and cookies are merged into the shared HttpClient** used by all scanners.

## 3.8 HTTP Client Infrastructure

**File:** `utils/http_client.py` — Async httpx with safety features

| Feature | Implementation |
|---------|---------------|
| **Scope enforcement** | Every request checked against `Scope.is_in_scope()` — raises `ScopeViolationError` |
| **Rate limiting** | `RateLimiter`: async lock-based delay between requests (configurable via config or policy) |
| **Concurrency control** | `asyncio.Semaphore(HTTP_CONCURRENCY)` limits parallel connections |
| **Retry with backoff** | Up to `HTTP_MAX_RETRIES` retries with exponential backoff (`2^attempt` seconds) |
| **Request logging** | Every request logged as `(method, url, status_code)` tuple |
| **Raw request capture** | `_build_raw_request()` generates HTTP/1.1 text for inclusion in findings |
| **No-redirect mode** | `request_no_redirect()` creates a separate client with `follow_redirects=False` to expose raw 3xx responses |
| **Proxy support** | Optional HTTP proxy passthrough (e.g., Burp Suite) |
| **SSL verification** | Enabled by default (`verify=True`); use `--insecure` to disable for local testing |

## 3.9 BaseScanner Framework

**File:** `core/base_scanner.py` — Abstract base class for all 17 scanners

Every scanner extends `BaseScanner` and inherits:

| Member | Type | Purpose |
|--------|------|---------|
| `self.client` | `HttpClient` | Scope-aware, rate-limited, retrying HTTP client |
| `self.logger` | `Logger` | Scoped to `scanner.<name>` for filtering |
| `self.name` | `str` | Scanner identifier (must match registry key) |
| `self.description` | `str` | Human-readable description |
| `self.tags` | `List[str]` | Category tags for filtering (e.g., `["injection", "owasp-a03"]`) |

| Method | Signature | Purpose |
|--------|-----------|---------|
| `run(state)` | `async → List[Finding]` | **Abstract** — main scan logic, must be implemented |
| `setup()` | `async → None` | Optional pre-scan initialization |
| `teardown()` | `async → None` | Optional post-scan cleanup |
| `test_payload(url, method, param, payload, inject_in)` | `async → (Response, raw_req)` | Inject payload into query/body/header/json parameter |
| `test_payload_no_redirect(...)` | `async → (Response, raw_req)` | Same but exposes raw 3xx responses |
| `make_finding(**kwargs)` | `→ Finding` | Create Finding with `module` auto-set to scanner name |

**Injection modes (`inject_in`):**
- `"query"` — payload injected into URL query parameter
- `"body"` — payload sent as POST form data
- `"header"` — payload set as HTTP header value
- `"json"` — payload sent as JSON body field

---

# 4. Scanner Modules — In-Depth Documentation

## 4.1 SQL Injection Scanner

**File:** `scanners/injection/sql_injection.py`
**Class:** `SQLInjectionScanner`
**CWE:** CWE-89 | **OWASP:** A03:2021 - Injection

### Algorithm

The scanner tests every discovered parameter with three distinct detection techniques executed sequentially per parameter:

#### Technique 1: Error-Based Detection (CRITICAL)

**Payloads (10):**
```
'   "   ''   \'   ' OR 1=1--   ' OR 1=1#
1' ORDER BY 100--   ' UNION SELECT NULL--
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--
' AND 1=CONVERT(int,'a')--
```

**Detection:** Response body is scanned against 14 regex signatures covering 6 database engines:

| Database | Signatures |
|----------|-----------|
| MySQL | `SQL syntax.*?MySQL`, `Warning.*?\Wmysql_`, `MySQLSyntaxErrorException` |
| Oracle | `ORA-\d{4,5}`, `Oracle.*?Driver` |
| MSSQL | `Microsoft.*?ODBC.*?SQL Server`, `Unclosed quotation mark` |
| PostgreSQL | `pg_query.*?failed`, `PSQLException`, `org\.postgresql\.` |
| SQLite | `sqlite3\.OperationalError` |
| Generic | `SQLSTATE`, `DB2 SQL error`, `invalid query`, `SQL command not properly ended` |

**False positive avoidance:** Regex matching ensures the signature is specific to database error messages, not generic text.

#### Technique 2: Time-Based Blind Detection (HIGH)

**Payloads (3):**

| Payload | Expected Delay | Target DB |
|---------|---------------|-----------|
| `' AND SLEEP(5)--` | 5s | MySQL |
| `'; WAITFOR DELAY '0:0:5'--` | 5s | MSSQL |
| `' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--` | 5s | MySQL (nested) |

**Detection:** `time.monotonic()` measures response time. Finding confirmed if `elapsed >= sleep_sec * 0.8` (20% tolerance for network jitter).

#### Technique 3: Boolean-Based Blind Detection (HIGH)

**Process:**
1. Send TRUE condition: `' AND 1=1--`
2. Send FALSE condition: `' AND 1=2--`
3. Send baseline value: `1`
4. Compare response lengths: `len(TRUE)`, `len(FALSE)`, `len(baseline)`
5. **Confirmed if:** `|TRUE - baseline| < 50` AND `|FALSE - baseline| > 100`

This ensures the TRUE response matches the baseline (normal behavior) while the FALSE response is noticeably different.

---

## 4.2 SSTI Scanner

**File:** `scanners/injection/ssti.py`
**Class:** `SSTIScanner`
**CWE:** CWE-94 | **OWASP:** A03:2021 - Injection

### Algorithm

Tests every discovered parameter with 7 template expression payloads across multiple template engines:

**Payloads:**

| Payload | Expected Output | Template Engines |
|---------|----------------|-----------------|
| `{{79831*79832}}` | `6375624792` | Jinja2, Twig, Nunjucks |
| `${79831*79832}` | `6375624792` | Freemarker, Velocity, Thymeleaf |
| `#{79831*79832}` | `6375624792` | Ruby ERB, Spring EL |
| `<%= 79831*79832 %>` | `6375624792` | ERB, JSP |
| `{{7*'7'}}` | `7777777` | Jinja2 (string multiplication) |
| `{79831*79832}` | `6375624792` | Smarty |
| `@(79831*79832)` | `6375624792` | Razor (.NET) |

**False positive avoidance:**
1. **Large-number canary:** Uses `79831*79832 = 6375624792` instead of `7*7 = 49` — the result `6375624792` never appears naturally in web pages (prices, dates, IDs, etc.)
2. **Baseline check:** Before testing, sends a harmless value and checks if `6375624792` already appears in the response. If it does, the parameter is skipped.
3. **Deduplication:** Uses `(url, parameter)` set to report at most one finding per parameter regardless of how many template engines succeed.

**Escalation PoC:** On confirmation, the scanner suggests RCE escalation: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`

---

## 4.3 CRLF Injection Scanner

**File:** `scanners/injection/crlf_injection.py`
**Class:** `CRLFInjectionScanner`
**CWE:** CWE-113 | **OWASP:** A03:2021 - Injection

### Algorithm

Tests every discovered parameter with 9 CRLF payloads covering multiple encoding schemes:

**Payloads:**

| Payload | Purpose |
|---------|---------|
| `%0d%0aInjected-Header:BugBountyAgent` | Standard CRLF header injection |
| `%0d%0a%0d%0a<script>alert(1)</script>` | Response splitting → XSS |
| `%0D%0ASet-Cookie:crlf=injected` | Session fixation via cookie injection |
| `\r\nX-Injected: true` | Raw CRLF (no encoding) |
| `%E5%98%8A%E5%98%8DInjected:true` | Unicode CRLF bypass |
| `%0d%0aLocation:%20https://evil.com` | Open redirect via CRLF |
| `%23%0d%0aHeader-Inject:true` | Hash + CRLF (fragment bypass) |
| `%%0d0d%%0a0aInjected:true` | Double encoding |
| `%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200` | Full response splitting |

**Detection — two attack classes:**

1. **Header injection (MEDIUM/HIGH):** Checks if `BugBountyAgent` appears in response headers. Severity upgraded to HIGH if `Set-Cookie` or `Location` headers are injected.

2. **Response splitting (HIGH):** Checks if `<script>` and `alert(1)` appear in the response body, indicating the injected content broke out of headers into the body.

---

## 4.4 Command Injection Scanner

**File:** `scanners/injection/command_injection.py`
**Class:** `CommandInjectionScanner`
**CWE:** CWE-78 | **OWASP:** A03:2021 - Injection

### Algorithm

Two-phase testing with parameter prioritization:

**Phase 1 — Parameter Triage:**
Parameters are classified as "suspicious" if their name matches common OS command parameters:
```
cmd, exec, command, run, ping, query, jump, file, filename, path,
dir, folder, log, ip, host, hostname, target, domain, url, daemon,
upload, download, process, execute, email, to, from, src, source, dest
```
- **Suspicious params:** test both time-based AND output-based payloads
- **Other params:** test time-based only (lower noise)

**Phase 2a — Time-Based Blind Detection (CRITICAL):**

| Payload | Delay | OS |
|---------|-------|-----|
| `;sleep 5;` | 5s | Linux |
| `\|sleep 5\|` | 5s | Linux |
| `` `sleep 5` `` | 5s | Linux |
| `$(sleep 5)` | 5s | Linux |
| `%0asleep 5%0a` | 5s | Linux |
| `& ping -n 5 127.0.0.1 &` | 5s | Windows |
| `\| ping -n 5 127.0.0.1` | 5s | Windows |
| `\nping -n 5 127.0.0.1\n` | 5s | Windows |

**Detection:** Measures baseline response time first, then checks if injected response time ≥ `baseline + delay - 1s`.

**Phase 2b — Output-Based Detection (CRITICAL):**

| Payload | Signatures | OS |
|---------|-----------|-----|
| `;id;` | `uid=`, `gid=` | Linux |
| `\|id` | `uid=`, `gid=` | Linux |
| `` `id` `` | `uid=`, `gid=` | Linux |
| `$(id)` | `uid=`, `gid=` | Linux |
| `;cat /etc/passwd;` | `root:x:0` | Linux |
| `$(cat /etc/passwd)` | `root:x:0` | Linux |
| `& echo CMDINJTEST1337` | `CMDINJTEST1337` | Windows |
| `\| type C:\windows\win.ini` | `[fonts]`, `[extensions]` | Windows |

**False positive avoidance:** Uses `uid=` and `gid=` (from `id` command) as signatures instead of `whoami` output, since `whoami` usernames are short strings that could appear naturally in page content.

---

## 4.5 XXE Scanner

**File:** `scanners/injection/xxe_scanner.py`
**Class:** `XXEScanner`
**CWE:** CWE-611 | **OWASP:** A05:2021 - Security Misconfiguration

### Algorithm

**Target discovery:** Two approaches run in parallel:
1. **Parameter endpoints:** All discovered URL+parameter combinations
2. **Common XML paths:** `/api/xml`, `/soap`, `/wsdl`, `/xmlrpc.php`, `/api/upload`, `/api/import`, `/api/parse`, `/feed`, `/rss`, `/sitemap.xml`

**8 payload categories:**

| Payload | Type | Signatures | Severity |
|---------|------|-----------|----------|
| Basic file read (`file:///etc/passwd`) | File read | `root:x:0` | CRITICAL |
| Windows file read (`file:///c:/windows/win.ini`) | File read | `[fonts]`, `[extensions]` | CRITICAL |
| Parameter entity (`%xxe;`) | Blind XXE | — | LOW (parser detected) |
| SSRF via XXE (`http://169.254.169.254/...`) | Cloud SSRF | `ami-id`, `instance-id` | CRITICAL |
| XInclude (`xi:include`) | File include | `root:x:0` | CRITICAL |
| SVG XXE (SVG with entity) | File read via SVG | `root:x:0` | CRITICAL |
| SOAP XXE (SOAP envelope with entity) | File read via SOAP | `root:x:0` | CRITICAL |
| Billion laughs (entity expansion) | DoS detection | timeout/error | LOW |

**Injection approaches per endpoint:**
1. **Raw XML body:** Send complete XML payload as POST body with `Content-Type: application/xml`
2. **Parameter injection:** Inject XML payloads into individual form/query parameters (top 3 payloads per param to limit noise)

**XML parser detection:** If response contains XML parsing errors (`xml parsing error`, `entityref`, `parser error`), the scanner creates a LOW-severity finding indicating blind XXE may be possible.

---

## 4.6 GraphQL Scanner

**File:** `scanners/injection/graphql_scanner.py`
**Class:** `GraphQLScanner`
**CWE:** Multiple | **OWASP:** A01, A04

### Algorithm

**Step 1 — Endpoint Discovery:**
Tests 8 common GraphQL paths (`/graphql`, `/graphql/v1`, `/api/graphql`, `/gql`, `/query`, `/graphiql`) by sending `{ __typename }` and checking for `data` or `errors` in the JSON response. Also checks discovered URLs for "graphql" or "gql" substrings.

**Step 2 — 6 parallel vulnerability checks:**

| Check | Vuln Type | Severity | Detection |
|-------|-----------|----------|-----------|
| **Introspection** | `graphql_introspection` (CWE-200) | MEDIUM | Send `{ __schema { types { name fields { name } } } }` — if `__schema` present in response data, schema is exposed |
| **BOLA/IDOR** | `graphql_bola` (CWE-639) | HIGH | Send 4 queries with sequential IDs (`user(id:1)`, `user(id:2)`, `users`, `orders`). Check if response contains sensitive fields (`email`, `phone`, `address`, `role`, `password`, `ssn`, `credit`) |
| **Depth DoS** | `graphql_dos` (CWE-400) | MEDIUM | Send 8-level nested query. If server processes it without depth limiting, vulnerable |
| **Batch Abuse** | `graphql_batch` (CWE-307) | LOW | Send array of 10 `{ __typename }` queries. If server returns 10 results, batch queries are allowed → brute-force amplification |
| **SQL Injection** | `graphql_sqli` (CWE-89) | CRITICAL | Inject SQL payloads in GraphQL arguments. Detect DB error messages in response |
| **Field Suggestions** | `graphql_field_suggestion` (CWE-200) | LOW | Send invalid field name. If response includes "Did you mean..." suggestions, schema information leaks |

---

## 4.7 XSS Scanner

**File:** `scanners/xss/xss_scanner.py`
**Class:** `XSSScanner`
**CWE:** CWE-79 | **OWASP:** A03:2021 - Injection

### Algorithm

**Two detection modes running in parallel:**

#### Mode 1: Reflected XSS (HIGH)

Tests every discovered parameter with 10 payloads, each tagged with a unique canary UUID:

**Payloads:**
```html
<script>alert(1)</script>
"><script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><svg onload=alert(1)>
javascript:alert(1)
<details open ontoggle=alert(1)>
<body onload=alert(1)>
"-alert(1)-"
<ScRiPt>alert(1)</sCrIpT>
```

**Canary tagging:** `alert(1)` is replaced with `alert('xss<uuid>')` where `<uuid>` is a random 8-character hex string per scan. This prevents false positives from other scripts on the page.

**Detection:** Exact match of the tagged payload in the response body. If the full payload appears unencoded, the input is reflected without sanitization.

#### Mode 2: DOM XSS Sink Detection (MEDIUM)

Scans all discovered JavaScript files for dangerous DOM manipulation patterns:

**Sinks checked:**
```
document.write    innerHTML    outerHTML    insertAdjacentHTML
eval(             setTimeout(  location.href  document.URL
```

**Process:** For each JS file URL in `target.metadata["js_files"]`, fetch the file and search for sink patterns. One finding per file (first sink found).

**Note:** DOM XSS detection is static analysis only — it identifies the sink but does not trace data flow from source to sink.

---

## 4.8 SSRF Scanner

**File:** `scanners/ssrf/ssrf_scanner.py`
**Class:** `SSRFScanner`
**CWE:** CWE-918 | **OWASP:** A10:2021 - SSRF

### Algorithm

**Parameter filtering:** Only tests parameters whose name matches 14 known URL-accepting parameter names OR if the payload targets cloud metadata (`169.254`):
```
url, uri, path, src, source, dest, destination, redirect, next,
data, reference, site, html, callback, return, view, image, img,
load, fetch, request, feed, host, proxy
```

**Payloads (8):**

| Payload | Target | Type |
|---------|--------|------|
| `http://127.0.0.1/` | Localhost | Internal |
| `http://localhost/` | Localhost | Internal |
| `http://0.0.0.0/` | All interfaces | Internal |
| `http://169.254.169.254/latest/meta-data/` | AWS EC2 metadata | Cloud |
| `http://metadata.google.internal/computeMetadata/v1/` | GCP metadata | Cloud |
| `http://169.254.169.254/metadata/instance` | Azure metadata | Cloud |
| `http://0x7f000001/` | Localhost (hex IP) | Bypass |
| `http://2130706433/` | Localhost (decimal IP) | Bypass |

**Detection signatures (7 regex):**
```
root:x:0:0    SSH-\d    redis_version
AMI ID        instance-id    computeMetadata    iam/security-credentials
```

**Severity classification:**
- **CRITICAL:** Cloud metadata payloads (`169.254` or `metadata` in URL) — leads to IAM credential theft
- **HIGH:** Internal service access — can pivot to internal network

---

## 4.9 Auth Scanner

**File:** `scanners/auth/auth_scanner.py`
**Class:** `AuthScanner`
**CWE:** CWE-347, CWE-1392, CWE-640, CWE-601 | **OWASP:** A07:2021

### Algorithm

Four parallel checks:

#### Check 1: JWT `alg:none` Attack (CRITICAL)

1. Fetch target URL, collect all response cookies and headers
2. Extract JWT tokens: any value starting with `eyJ` and containing exactly 2 dots
3. Parse the JWT header (Base64 decode)
4. Craft a new token with `{"alg":"none","typ":"JWT"}` header, same payload, empty signature
5. Send request with `Authorization: Bearer <none_token>`
6. If server returns HTTP 200, the server accepts unsigned JWTs → complete auth bypass

#### Check 2: Default Credentials (CRITICAL)

Tests 5 admin paths (`/admin`, `/login`, `/wp-admin`, `/administrator`, `/panel`) with 4 credential pairs:
- `admin:admin`, `admin:password`, `admin:123456`, `root:root`

**Process:** GET the login page → check for login form indicators → POST credentials → check for dashboard/logout/welcome indicators in response.

#### Check 3: Password Reset Host Header Injection (HIGH)

Tests 3 password reset paths (`/forgot-password`, `/reset-password`, `/password-reset`) by submitting a password reset with `Host: evil.com`. If `evil.com` appears in the response, the reset link can be poisoned to capture reset tokens.

#### Check 4: OAuth Open Redirect (HIGH)

Scans discovered URLs for OAuth/authorize/callback endpoints. Appends `redirect_uri=https://evil.com` and checks if the server redirects to `evil.com` — allowing token theft via OAuth flow manipulation.

---

## 4.10 CSRF Scanner

**File:** `scanners/auth/csrf_scanner.py`
**Class:** `CSRFScanner`
**CWE:** CWE-352 | **OWASP:** A01:2021 - Broken Access Control

### Algorithm

Analyzes up to 50 discovered URLs for CSRF vulnerabilities:

**Step 1 — Form Discovery:**
Parses HTML for `<form>` tags, extracting method and action attributes. Only POST/PUT/DELETE/PATCH forms are CSRF targets (GET forms are excluded by design).

**Step 2 — Protection Check (3 layers):**

| Protection | Detection Method |
|-----------|-----------------|
| CSRF token | Regex: 12 patterns including `csrf`, `_token`, `authenticity_token`, `__RequestVerificationToken`, `csrfmiddlewaretoken`, `_csrf`, `nonce`, `_wpnonce`, `x-csrf-token`, `x-xsrf-token` |
| SameSite cookie | Parse `Set-Cookie` headers for `SameSite=Strict` or `SameSite=Lax` |
| Custom header requirement | Check if page JS references `X-Requested-With`, `X-CSRF`, `x-xsrf-token` |

**Step 3 — Severity Assessment:**
If no protection found, severity is determined by form context:
- **HIGH:** Forms containing keywords: `password`, `email`, `delete`, `admin`, `transfer`, `payment`, `withdraw`, `account`, `settings`, `role`
- **MEDIUM:** All other unprotected forms

**Step 4 — Token Validation Bypass Test:**
If a CSRF token IS present, the scanner tests whether the server actually validates it:
1. Extract all form fields including the token
2. Replace the token value with `INVALID_TOKEN_TEST`
3. Submit the form with the invalid token
4. If the server returns 200/301/302, the token is not validated server-side → `csrf_token_bypass` finding (HIGH)

---

## 4.11 Race Condition Scanner

**File:** `scanners/auth/race_condition.py`
**Class:** `RaceConditionScanner`
**CWE:** CWE-362 | **OWASP:** A04:2021 - Insecure Design

### Algorithm

**Target selection:** Only tests endpoints whose URLs contain business-logic keywords:
```
coupon, discount, redeem, apply, promo, transfer, withdraw, send,
vote, like, follow, invite, claim, reward, bonus, checkout, order,
purchase, subscribe, verify, confirm, activate, use
```

**Testing methodology:**
1. Fire **10 concurrent identical requests** using `asyncio.gather()`
2. Collect response metadata: HTTP status, response length, response time, body hash (first 500 chars)
3. Analyze results for TOCTOU indicators

**Race condition indicators (4):**

| Indicator | Detection | Meaning |
|-----------|-----------|---------|
| Mixed status codes | Multiple unique statuses with >1 success (200/201/302) | Server inconsistently handles concurrent requests |
| All success | Every request returned 200/201/302 | Action possibly executed multiple times (e.g., coupon applied 10x) |
| Varied responses | Response body hashes differ but aren't all unique | Different outcomes for identical requests = race window |
| Length variance | `max(lengths) - min(lengths) > 100 bytes` | Responses differ significantly in size |

**Positive detection requires:** mixed status codes OR (varied responses AND significant length variance).

---

## 4.12 IDOR Scanner

**File:** `scanners/authz/idor_scanner.py`
**Class:** `IDORScanner`
**CWE:** CWE-639 | **OWASP:** A01:2021 - Broken Access Control

### Algorithm

**Parameter filtering:** Only tests parameters with ID-like names:
```
id, user_id, userId, account_id, order_id, profile_id,
doc_id, file_id, record_id, item_id, uid, pid
```

**Three-request comparison technique:**
1. Request with `param=1` (first user's data)
2. Request with `param=2` (second user's data)
3. Request with `param=9999999999` (non-existent ID → baseline)

**Detection logic:**
- Both `param=1` and `param=2` return HTTP 200
- Response lengths for ID=1 and ID=2 differ by >50 bytes (different user data)
- Baseline (non-existent ID) looks different: either <1000 bytes OR less than 50% of the shortest valid response
- This three-point comparison ensures the endpoint actually has different data for different IDs, and the baseline confirms that non-existent IDs are handled differently

---

## 4.13 Path Traversal Scanner

**File:** `scanners/file/path_traversal.py`
**Class:** `PathTraversalScanner`
**CWE:** CWE-22 | **OWASP:** A01:2021 - Broken Access Control

### Algorithm

**Parameter filtering:** Only tests file-related parameter names:
```
file, path, page, template, include, doc, document,
filename, filepath, folder, dir, load, read, view, resource
```

**Payloads (8) — covering multiple encoding and OS variants:**

| Payload | Encoding | Target OS |
|---------|----------|-----------|
| `../../../etc/passwd` | None | Linux |
| `..%2F..%2F..%2Fetc%2Fpasswd` | URL encoded `/` | Linux |
| `..%252F..%252F..%252Fetc%252Fpasswd` | Double URL encoded | Linux |
| `....//....//....//etc/passwd` | Double-dot-slash bypass | Linux |
| `/%2e%2e/%2e%2e/%2e%2e/etc/passwd` | URL encoded dots | Linux |
| `php://filter/convert.base64-encode/resource=/etc/passwd` | PHP wrapper | PHP |
| `..\..\..\windows\win.ini` | Backslash | Windows |
| `..\..\..\windows\system32\drivers\etc\hosts` | Backslash | Windows |

**Detection signatures (6 regex):**
```
root:x:0:0          root:.*:/bin/(bash|sh)
\[fonts\]            \[extensions\]
localhost            127\.0\.0\.1
```

Signatures are matched to their corresponding payloads — `/etc/passwd` payloads check for `root:x:0`, Windows payloads check for `[fonts]`.

---

## 4.14 Misconfiguration Scanner

**File:** `scanners/misconfig/misconfig_scanner.py`
**Class:** `MisconfigScanner`
**CWE:** CWE-200, CWE-527, CWE-530, CWE-548, CWE-693, CWE-942 | **OWASP:** A05:2021

### Algorithm

Four parallel detection categories:

#### Category 1: Sensitive File Exposure (16 paths)

| Path | Finding | Severity | Validation |
|------|---------|----------|------------|
| `/.git/HEAD` | Exposed Git Repository | HIGH | Must contain `ref: refs/` |
| `/.env` | Exposed .env File | CRITICAL | Must contain `=` |
| `/.env.production` | Exposed .env.production | CRITICAL | Presence check only |
| `/wp-config.php` | WordPress Config | CRITICAL | HTTP 200 + content |
| `/actuator/env` | Spring Actuator | CRITICAL | Presence check only |
| `/phpinfo.php` | PHP Info Exposed | MEDIUM | Presence check only |
| `/debug` | Debug Endpoint | MEDIUM | Presence check only |
| `/_profiler` | Symfony Profiler | HIGH | Presence check only |
| `/graphiql` | GraphiQL IDE | MEDIUM | Presence check only |
| `/actuator/heapdump` | Heap Dump | CRITICAL | Presence check only |
| `/error.log` | Error Log | HIGH | Presence check only |
| `/backup.zip` | Backup File | HIGH | Presence check only |
| `/db_backup.sql` | Database Backup | CRITICAL | Presence check only |
| `/package.json` | package.json | MEDIUM | Presence check only |
| `/.svn/entries` | SVN Repository | HIGH | Presence check only |
| `/telescope` | Laravel Telescope | HIGH | Presence check only |

**Validation:** `.git/HEAD` requires `ref: refs/` to avoid false positives from custom 404 pages. `.env` requires `=` to distinguish from empty files.

#### Category 2: Security Header Audit (5 headers)

Checks for missing headers: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`. Each missing header generates a LOW severity finding.

#### Category 3: CORS Misconfiguration (2 tests)

| Test | Severity | Detection |
|------|----------|-----------|
| Wildcard `Access-Control-Allow-Origin: *` | LOW | Check ACAO header value |
| Arbitrary origin reflection with credentials | HIGH | Send `Origin: https://evil.com`, check if ACAO reflects it AND `Access-Control-Allow-Credentials: true` |

#### Category 4: Directory Listing (4 paths)

Tests `/`, `/uploads/`, `/static/`, `/images/` for directory listing signatures: `Index of /` (Apache), `<title>Directory listing` (generic), `[To Parent Directory]` (IIS).

---

## 4.15 Host Header Scanner

**File:** `scanners/misconfig/host_header.py`
**Class:** `HostHeaderScanner`
**CWE:** CWE-644 | **OWASP:** A05:2021

### Algorithm

**Target URL selection:** Tests the main URL plus any discovered URLs containing reset/auth-related keywords (`reset`, `forgot`, `password`, `register`, `confirm`, `activate`, `verify`, `invite`, `callback`).

**7 header manipulation payloads:**

| Header | Value | Attack |
|--------|-------|--------|
| `Host` | `evil.attacker.com` | Direct host injection |
| `X-Forwarded-Host` | `evil.attacker.com` | Reverse proxy bypass |
| `X-Host` | `evil.attacker.com` | Alternative host header |
| `X-Forwarded-Server` | `evil.attacker.com` | Server override |
| `X-Original-URL` | `/evil.attacker.com` | URL rewrite injection |
| `X-Rewrite-URL` | `/evil.attacker.com` | URL rewrite injection |
| `Forwarded` | `host=evil.attacker.com` | RFC 7239 forwarded header |

**Detection — 3 attack classes:**

| Attack | Detection | Severity |
|--------|-----------|----------|
| Password reset poisoning | `evil.attacker.com` in response body + URL contains reset keywords | HIGH |
| Host header injection (in link context) | `evil.attacker.com` in `href`/`src`/`action` attributes | HIGH |
| Host header injection (body) | `evil.attacker.com` anywhere in response body | MEDIUM |
| Host header redirect | `evil.attacker.com` in redirect `Location` header (no-redirect request) | HIGH |

**Web cache poisoning test:**
1. Add cache buster query param (`?cb=<hash>`)
2. Request 1: inject `X-Forwarded-Host: evil.attacker.com`
3. Request 2: normal request to same URL (no injection)
4. If Request 2 response still contains `evil.attacker.com`, the cache was poisoned → CRITICAL

---

## 4.16 Open Redirect Scanner

**File:** `scanners/redirect/open_redirect.py`
**Class:** `OpenRedirectScanner`
**CWE:** CWE-601 | **OWASP:** A01:2021

### Algorithm

**Parameter filtering:** Tests parameters with redirect-related names (25 names):
```
redirect, redirect_uri, redirect_url, return, return_url, returnTo,
next, url, rurl, dest, destination, redir, continue, target, view,
goto, out, link, forward, callback, path, to, checkout_url, login_url, image_url
```

**Payloads (10) — progressive bypass techniques:**

| Payload | Bypass Technique |
|---------|-----------------|
| `https://evil.com` | Direct URL |
| `//evil.com` | Protocol-relative |
| `/\evil.com` | Backslash confusion |
| `https://evil.com%2F%2F` | URL-encoded slashes |
| `////evil.com` | Multiple slashes |
| `https:evil.com` | Missing slashes |
| `https://target.com@evil.com` | URL auth section abuse |
| `https://target.com.evil.com` | Subdomain confusion |
| `java%0d%0ascript:alert(1)` | CRLF + JavaScript protocol |
| `data:text/html,<script>alert(1)</script>` | Data URI scheme |

**Detection — 2 modes:**

1. **No-redirect mode:** Uses `test_payload_no_redirect()` to capture raw 3xx responses. If `Location` header contains `evil.com`, confirmed redirect.
2. **Followed-redirect mode:** Follows the redirect and checks if `evil.com` appears in the final response body near redirect/location context.

**URL-based testing:** Also checks discovered URLs that contain redirect keywords (`redirect`, `return`, `next=`, `goto`, `redir`) in case they already have redirect parameters in the URL.

---

## 4.17 Subdomain Takeover Scanner

**File:** `scanners/recon/subdomain_takeover.py`
**Class:** `SubdomainTakeoverScanner`
**CWE:** CWE-284 | **OWASP:** A05:2021

### Algorithm

**Subdomain enumeration:**
1. **From discovered URLs:** Extract unique hostnames from all crawled URLs
2. **Generated subdomains:** Combine 36 common prefixes with the target's base domain:
   ```
   staging, dev, test, beta, alpha, demo, sandbox, api, api-dev,
   api-staging, cdn, mail, blog, docs, status, admin, portal, app,
   m, mobile, shop, store, support, help, assets, static, media,
   img, old, legacy, backup, ci, jenkins, git, gitlab
   ```
3. **Scope check:** Generated subdomains are only tested if they pass `scope.is_in_scope()`

**22 service fingerprints:**

| Service | CNAME Pattern | Response Signature |
|---------|--------------|-------------------|
| Amazon S3 | `.s3.amazonaws.com` | `NoSuchBucket` |
| Amazon S3 Website | `.s3-website*.amazonaws.com` | `NoSuchBucket` |
| GitHub Pages | `.github.io` | `There isn't a GitHub Pages site here` |
| Heroku | `.herokuapp.com` | `No such app` |
| Shopify | `.myshopify.com` | `Sorry, this shop is currently unavailable` |
| Tumblr | `.tumblr.com` | `There's nothing here` |
| WordPress.com | `.wordpress.com` | `Do you want to register` |
| Azure Web App | `.azurewebsites.net` | `404 Web Site not found` |
| Azure Cloud App | `.cloudapp.net` | `404 Web Site not found` |
| Azure API | `.azure-api.net` | `not found` |
| Azure Blob | `.blob.core.windows.net` | `BlobNotFound` |
| Azure Traffic Mgr | `.trafficmanager.net` | `404 Web Site not found` |
| Fastly | `.fastly.net` | `Fastly error: unknown domain` |
| Pantheon | `.pantheonsite.io` | `404 error unknown site` |
| Zendesk | `.zendesk.com` | `Help Center Closed` |
| Unbounce | `.unbouncepages.com` | `The requested URL was not found` |
| Surge.sh | `.surge.sh` | `project not found` |
| Bitbucket | `.bitbucket.io` | `Repository not found` |
| Ghost | `.ghost.io` | `The thing you were looking for is no longer here` |
| Netlify | `.netlify.app` | `Not Found - Request ID` |
| Fly.io | `.fly.dev` | `404 Not Found` |
| Vercel | `.vercel.app` | `DEPLOYMENT_NOT_FOUND` |

**Two-step verification (false positive prevention):**
1. **HTTP response check:** Response body must contain the service-specific signature
2. **DNS CNAME verification:** `nslookup -type=cname <hostname>` must return a CNAME record matching the service's domain pattern

Both conditions must be true — this prevents false positives from generic 404 pages that happen to contain service keywords.

---

# 5. Reconnaissance Subsystem

## 5.1 Crawler

**File:** `recon/crawler.py`

Async breadth-first web crawler that maps the target's attack surface:

**Process:**
```
                Initial URL (depth=0)
                    │
        ┌───────────▼────────────┐
        │   Queue: [(url, depth)] │
        │   Visited: set()        │
        └───────────┬────────────┘
                    │
        ┌───────────▼────────────────────────────┐
        │  For each URL in queue:                 │
        │  1. Skip if visited or out of scope     │
        │  2. HTTP GET request                    │
        │  3. Check Content-Type:                 │
        │     ├── HTML → extract links, forms,    │
        │     │          script sources            │
        │     └── JS → extract endpoints,          │
        │              detect secrets              │
        │  4. Extract query params from URL        │
        │  5. Add new URLs to queue (depth + 1)    │
        └────────────────────────────────────────┘
```

**HTML extraction (BeautifulSoup):**
- `<a href>` and `<link href>` → follow links
- `<form action>` + `<input name>` → discovered params
- `<script src>` → JS file URLs (added to `js_files`)

**JS analysis (6 regex patterns):**
- `["'](/path/to/endpoint)["']` — string literals
- `fetch(["']url["'])` — Fetch API calls
- `axios.method(["']url["'])` — Axios calls
- `url: ["']...["']` — config objects
- `endpoint: ["']...["']` — named endpoints
- `api_url: ["']...["']` — API URL configs

**Secret detection (7 patterns):**
- API keys (20+ char alphanumeric)
- Passwords/secrets (8+ char)
- AWS Access Key ID (`AKIAxxxxxxxxxx`)
- AWS Secret Key (40 char base64)
- AWS key pattern (`AKIA` prefix)
- Bearer tokens (20+ char)
- GitHub PATs (`ghp_` prefix)

## 5.2 Fingerprinter

**File:** `recon/fingerprint.py`

**Technology detection sources:**

| Source | Method | Technologies Detected |
|--------|--------|----------------------|
| `X-Powered-By` header | Regex matching | PHP, ASP.NET, Express.js, Next.js |
| `Server` header | Regex matching | Nginx, Apache, IIS, LiteSpeed, Cloudflare, S3 |
| `X-Drupal-Cache` header | Presence check | Drupal |
| `X-WP-Nonce` header | Presence check | WordPress |
| HTML body content | Regex matching | WordPress, Drupal, Joomla, Shopify, Magento, Laravel, Django, Next.js, React, Vue.js, Angular, jQuery, Bootstrap, GraphQL, Swagger UI |
| `Set-Cookie` values | String matching | PHP, Java EE, ASP, Laravel |

**Security header audit (9 headers):**
Checks for: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `X-XSS-Protection`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`

**Interesting headers collected:** `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, `X-Runtime`, `X-Version`, `Via`, `X-Cache`

---

# 6. Reporting Subsystem

**File:** `reporting/reporter.py`

### Report Formats

**Markdown report** includes:
- Target URL, scan ID, date, duration
- Executive summary (AI-generated or template)
- Statistics table: URLs tested, parameters tested, modules run, findings by severity
- Technologies detected
- Severity-sorted findings with emoji badges (🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM, 🔵 LOW, ⚪ INFO)
- Per-finding: status, severity, type, URL, parameter, CVSS, CWE, OWASP, payload, evidence, HTTP request, PoC steps, remediation, AI analysis
- Scan errors log
- Agent reasoning log (timestamped thoughts)

**JSON report** includes all fields as machine-readable data with ISO timestamps.

**HTML report** includes:
- Dark-themed CSS styling
- Severity-colored finding cards (left border + badge)
- Collapsible sections for payload/evidence/PoC
- Statistics overview with severity counts

### HackerOne Integration

**File:** `reporting/hackerone_api.py`

Supports auto-submission to HackerOne:
- API authentication via `H1_USERNAME` + `H1_API_TOKEN` environment variables
- Formats findings as HackerOne report structure with vulnerability type, severity, title, description, PoC steps
- Endpoints: create report, update report, get program scope

---

# 7. Quick Start

### Prerequisites

- Python 3.10+
- [Ollama](https://ollama.ai) running locally with a model pulled
- Dependencies: `pip install -r requirements.txt`

### Setup

```bash
# 1. Clone and install
git clone <repo-url> && cd AgentiAI
pip install -r requirements.txt

# 2. Start Ollama and pull a model
ollama serve
ollama pull llama3:8b

# 3. Verify everything works
python main.py --health-check

# 4. Run your first scan
python main.py --target https://testphp.vulnweb.com
```

### Common Usage Patterns

```bash
# Scoped scan with explicit scope definition
python main.py \
  --target https://app.example.com \
  --scope "*.example.com" "api.example.com" \
  --exclude "admin.example.com"

# Authenticated scan with cookies/headers
python main.py \
  --target https://app.example.com \
  --cookie "session=abc123" "csrf=xyz" \
  --header "Authorization:Bearer TOKEN"

# Scan through Burp Suite proxy
python main.py \
  --target https://example.com \
  --proxy http://127.0.0.1:8080

# Run specific modules only
python main.py \
  --target https://example.com \
  --modules sql_injection xss_scanner ssrf graphql_scanner

# Fast mode: rule engine only (no LLM)
python main.py \
  --target https://example.com \
  --no-ai --log-level DEBUG

# With bug bounty policy enforcement
python main.py \
  --target https://example.com \
  --policy policy.json --yes

# Resume an interrupted scan
python main.py --resume

# Form-based authenticated scanning
python main.py \
  --target https://example.com \
  --login-url https://example.com/login \
  --login-user admin --login-pass secret
```

---

# 8. CLI Reference

| Flag | Description |
|------|-------------|
| `--target`, `-t` | Target URL (required unless `--resume`) |
| `--scope`, `-s` | Allowed domains (supports wildcards: `*.example.com`) |
| `--exclude` | Excluded domains |
| `--modules`, `-m` | Specific scanner modules to run |
| `--proxy` | HTTP proxy URL (e.g. `http://127.0.0.1:8080`) |
| `--cookie` | Session cookies as `key=value` pairs |
| `--header` | Custom headers as `Key:Value` pairs |
| `--policy` | Path to BBP policy JSON file |
| `--yes`, `-y` | Auto-confirm pre-scan safety prompt |
| `--profile` | Load a saved scope profile by name |
| `--save-profile` | Save current config as a named profile |
| `--login-url` | Login URL for form-based authentication |
| `--login-user` | Username for form-based authentication |
| `--login-pass` | Password for form-based authentication |
| `--bearer-token` | Bearer token for API authentication |
| `--ollama-model` | Override the Ollama model (default: `llama3:8b`) |
| `--no-ai` | Disable LLM, use rule engine only |
| `--no-tui` | Disable the Rich live dashboard |
| `--no-memory` | Disable persistent scan memory |
| `--resume` | Resume an interrupted scan from checkpoint |
| `--reward-scheme` | Path to custom reward scheme JSON |
| `--health-check` | Run health checks and exit |
| `--log-level` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `--output-dir` | Output directory for reports (default: `./reports/`) |

---

# 9. Configuration

All settings are config-driven via `config/ai_hunter_config.json` with environment variable overrides.

### Key Configuration Sections

```
ai_hunter_config.json
├── ollama               # LLM settings: models, endpoints, timeouts, temperature
│   ├── models           #   primary: llama3:8b, fallback: mistral:7b
│   ├── timeouts         #   connect, read, health check timeouts
│   ├── parameters       #   temperature, top_p, top_k, context window
│   └── error_handling   #   auto-retry, model pull, context reduction
│
├── hackerone_api         # HackerOne API integration
│   ├── endpoints        #   programs, reports, scope
│   └── report_template  #   auto-populated fields for submission
│
├── scanning             # Scanner defaults
│   ├── rate_limit       #   requests per second
│   ├── timeout          #   per-module timeout
│   └── concurrency      #   max simultaneous requests
│
└── health_checks        # Startup health check sequence
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OLLAMA_URL` | `http://localhost:11434` | Ollama API base URL |
| `OLLAMA_MODEL` | `llama3:8b` | Primary LLM model |
| `OLLAMA_FALLBACK_MODEL` | `mistral:7b` | Fallback LLM model |
| `H1_USERNAME` | — | HackerOne API username |
| `H1_API_TOKEN` | — | HackerOne API token |

---

# 10. Adding New Scanners

```python
# 1. Create: scanners/your_category/my_scanner.py
from core.base_scanner import BaseScanner
from core.models import Finding, ScanState
from config.settings import Severity

class MyScanner(BaseScanner):
    name = "my_scanner"
    description = "Detects XYZ vulnerability"
    tags = ["category", "owasp-aXX"]

    async def run(self, state: ScanState) -> list[Finding]:
        findings = []
        for url, params in state.target.discovered_params.items():
            for param in params:
                resp, raw_req = await self.test_payload(
                    url, "GET", param, "payload_here", inject_in="query"
                )
                if resp and "signature" in resp.text:
                    findings.append(self.make_finding(
                        title=f"XYZ Vuln in '{param}'",
                        vuln_type="xyz_vuln",
                        severity=Severity.HIGH,
                        url=url, parameter=param, method="GET",
                        payload="payload_here",
                        evidence="signature found in response",
                        request=raw_req, response=resp.text[:500],
                        cwe_id="CWE-XXX",
                        owasp_category="AXX:2021 - Category",
                        description="Description of the vulnerability.",
                        poc_steps=["1. Step one", "2. Step two"],
                    ))
        return findings

# 2. Register in core/orchestrator.py → SCANNER_REGISTRY:
#    "my_scanner": ("scanners.your_category.my_scanner", "MyScanner"),
#
# 3. Add to config/settings.py → ENABLED_MODULES list
```

### Scanner API

Every scanner extends `BaseScanner` and gets:

| Method | Description |
|--------|-------------|
| `self.client` | Scope-aware async HTTP client with rate limiting |
| `self.test_payload(url, method, param, payload, inject_in=)` | Inject payload into query/body/header/json and return `(response, raw_request)` |
| `self.test_payload_no_redirect(...)` | Same as above but does not follow 3xx redirects |
| `self.make_finding(**kwargs)` | Create a `Finding` with the scanner's module name auto-set |
| `self.logger` | Logger scoped to `scanner.<name>` |

---

# 11. Legal Notice

> **Only use against systems you have explicit written permission to test.**

This tool performs active scanning that may trigger WAFs, IDS/IPS, and security alerts.
The scope enforcement and BBP policy engine are safeguards — **you are responsible for ensuring proper authorization.**
