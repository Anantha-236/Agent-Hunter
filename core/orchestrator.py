"""
Main Orchestrator -- coordinates the full scan pipeline.
Integrates: reward engine, Ollama/rule AI brain, memory system, TUI,
            WAF bypass, auth sessions, payload learning, and scan resume.
"""
from __future__ import annotations
import asyncio
import importlib
import json
import logging
import os
from datetime import datetime
from typing import List, Optional, Type

from config.settings import ENABLED_MODULES, SCAN_TIMEOUT_PER_MODULE, RL_REWARD_MAP
from core.Hunter_brain import AIBrain
from core.base_scanner import BaseScanner
from core.bbp_policy import BBPPolicy, PolicyEnforcer
from core.memory import ScanMemory
from core.models import Finding, ScanState, Target
from core.pre_engagement import (
    PreEngagementChecklist, PreEngagementGate, PreEngagementResult,
    print_pre_engagement_banner,
)
from core.reward import RewardEngine
from core.rl_agent import RLPolicyAgent
from core.rl_environment import EnvironmentState
from core.waf_engine import WAFEngine
from core.auth_session import AuthSession
from core.payload_engine import AdaptivePayloadEngine
from recon.crawler import Crawler
from recon.fingerprint import Fingerprinter
from utils.http_client import HttpClient

logger = logging.getLogger(__name__)

# ── Scanner Registry ──────────────────────────────────────────
SCANNER_REGISTRY = {
    "sql_injection":       ("scanners.injection.sql_injection",     "SQLInjectionScanner"),
    "ssti":                ("scanners.injection.ssti",               "SSTIScanner"),
    "crlf_injection":      ("scanners.injection.crlf_injection",     "CRLFInjectionScanner"),
    "xss_scanner":         ("scanners.xss.xss_scanner",             "XSSScanner"),
    "ssrf":                ("scanners.ssrf.ssrf_scanner",            "SSRFScanner"),
    "auth_scanner":        ("scanners.auth.auth_scanner",            "AuthScanner"),
    "idor_scanner":        ("scanners.authz.idor_scanner",           "IDORScanner"),
    "path_traversal":      ("scanners.file.path_traversal",          "PathTraversalScanner"),
    "misconfig_scanner":   ("scanners.misconfig.misconfig_scanner",  "MisconfigScanner"),
    "open_redirect":       ("scanners.redirect.open_redirect",       "OpenRedirectScanner"),
    "subdomain_takeover":  ("scanners.recon.subdomain_takeover",     "SubdomainTakeoverScanner"),
    "csrf_scanner":        ("scanners.auth.csrf_scanner",            "CSRFScanner"),
    "host_header":         ("scanners.misconfig.host_header",        "HostHeaderScanner"),
    "xxe_scanner":         ("scanners.injection.xxe_scanner",        "XXEScanner"),
    "race_condition":      ("scanners.auth.race_condition",          "RaceConditionScanner"),
    "command_injection":   ("scanners.injection.command_injection",  "CommandInjectionScanner"),
    "graphql_scanner":     ("scanners.injection.graphql_scanner",    "GraphQLScanner"),
}

CHECKPOINT_FILE = "scan_checkpoint.json"


def load_scanner(name: str) -> Optional[Type[BaseScanner]]:
    if name not in SCANNER_REGISTRY:
        return None
    module_path, class_name = SCANNER_REGISTRY[name]
    try:
        mod = importlib.import_module(module_path)
        return getattr(mod, class_name)
    except Exception as exc:
        logger.warning(f"Failed to load scanner '{name}': {exc}")
        return None


class Orchestrator:
    def __init__(self, target: Target, modules=None, use_ai=True,
                 proxy=None, cookies=None, headers=None,
                 use_tui=True, use_memory=True, reward_scheme=None,
                 auth_session=None, policy: BBPPolicy = None,
                 pre_engagement_checklist: PreEngagementChecklist = None,
                 auto_confirm: bool = False, verify_ssl: bool = True):
        self.target = target
        self.modules = modules or list(SCANNER_REGISTRY.keys())
        self.use_ai = use_ai
        self.proxy = proxy
        self.auto_confirm = auto_confirm
        self.verify_ssl = verify_ssl
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.use_tui = use_tui
        self._client = None

        # -- Core systems --
        self.ai = AIBrain()
        self.reward = RewardEngine(reward_scheme=reward_scheme)
        self.rl = RLPolicyAgent(
            modules=self.modules,
            state_file=os.path.join("reports", "rl_policy_state.json"),
            exploration_strategy="hybrid",
        )
        self._scan_start_time = 0.0
        self._module_rewards: Dict[str, float] = {}
        self.rl_reward_map = RL_REWARD_MAP or {
            "confirmed_finding": 50,
            "successful_exploit": 100,
            "duplicate_finding": -30,
            "high_severity_found": 40,
            "critical_severity_found": 80,
            "no_progress_action": -5,
            "incorrect_exploit_attempt": -10,
        }
        self.memory = ScanMemory() if use_memory else None
        self.waf = WAFEngine()
        self.auth = auth_session or AuthSession()
        self.payload_engine = AdaptivePayloadEngine()
        self._tui = None

        # -- Policy & Pre-Engagement Gate --
        self.policy = policy
        self.policy_enforcer = PolicyEnforcer(policy) if policy else None
        self._pre_engagement_checklist = pre_engagement_checklist
        self._pre_engagement_result: Optional[PreEngagementResult] = None

    async def __aenter__(self):
        # Merge auth cookies/headers if authenticated
        merged_cookies = {**self.cookies, **self.auth.get_auth_cookies()}
        merged_headers = {**self.headers, **self.auth.get_auth_headers()}

        self._client = HttpClient(
            scope=self.target.scope, cookies=merged_cookies,
            headers=merged_headers, proxy=self.proxy,
            verify_ssl=self.verify_ssl,
            policy_enforcer=self.policy_enforcer,
        )
        await self._client.__aenter__()

        # Start TUI
        if self.use_tui:
            try:
                from utils.console import ScanConsole
                self._tui = ScanConsole()
                self._tui.start(self.target.url)
            except Exception as exc:
                logger.debug(f"TUI unavailable: {exc}")

        return self

    async def __aexit__(self, *args):
        if self._tui:
            self._tui.stop()
        if self._client:
            await self._client.__aexit__(*args)
        if self.memory:
            self.memory.close()
        self.ai.close()
        self.payload_engine.close()

    # ── Main Pipeline ─────────────────────────────────────────

    def _build_env_state(self, state: ScanState, remaining: list = None) -> EnvironmentState:
        """Build an RL EnvironmentState from the current ScanState."""
        import time
        from collections import Counter
        sev_counts = Counter(f.severity for f in state.findings)
        vuln_types = set(f.vuln_type for f in state.findings)
        return EnvironmentState(
            target_url=self.target.url,
            technologies=self.target.technologies or [],
            waf_detected=bool(self.target.metadata.get("waf")),
            waf_name=self.target.metadata.get("waf", ""),
            discovered_urls_count=len(self.target.discovered_urls),
            discovered_params_count=len(self.target.discovered_params),
            ssl_present=self.target.url.startswith("https"),
            modules_run=list(state.modules_run),
            modules_remaining=remaining or list(state.modules_pending),
            findings_count=len(state.findings),
            confirmed_count=sum(1 for f in state.findings if f.confirmed),
            severity_counts=dict(sev_counts),
            unique_vuln_types=vuln_types,
            duplicate_count=0,
            cumulative_reward=self.reward.total_score,
            last_reward=self._module_rewards.get(state.modules_run[-1], 0.0) if state.modules_run else 0.0,
            rewards_history=list(self._module_rewards.values()),
            elapsed_seconds=time.monotonic() - self._scan_start_time,
            avg_module_time=(
                (time.monotonic() - self._scan_start_time) / max(len(state.modules_run), 1)
            ),
            module_last_reward=dict(self._module_rewards),
            step=len(state.modules_run),
        )

    async def run(self, resume_from: str = None) -> ScanState:
        import time as _time
        self._scan_start_time = _time.monotonic()

        state = ScanState(target=self.target)
        state.log_thought("Scan started")

        # Start RL episode (Feature 9: Episode lifecycle)
        self.rl.start_episode(episode_id=state.scan_id)

        if self.memory:
            self.memory.start_scan(state.scan_id, self.target.url)

        if resume_from:
            state = self._load_checkpoint(state, resume_from)

        try:
            # Phase 0: Pre-Engagement Gate
            if state.phase in ("init",):
                gate_passed = await self._phase_pre_engagement(state)
                if not gate_passed:
                    state.phase = "aborted"
                    state.ended_at = datetime.utcnow()
                    state.log_thought("Scan ABORTED by pre-engagement gate")
                    self._update_tui("complete")
                    return state

            # Phase 1: Recon
            if state.phase in ("init", "recon"):
                state.phase = "recon"
                self._update_tui("recon")
                await self._phase_recon(state)
                self._save_checkpoint(state)

            # Phase 2: AI Strategy
            if state.phase in ("recon", "strategy"):
                state.phase = "strategy"
                self._update_tui("strategy")
                if self.use_ai:
                    await self._phase_strategy(state)
                else:
                    state.modules_pending = list(self.modules)
                self._save_checkpoint(state)

            # Phase 3: Scanning
            if state.phase in ("strategy", "scan"):
                state.phase = "scan"
                self._update_tui("scan")
                await self._phase_scan(state)
                self._save_checkpoint(state)

            # Phase 4: Validation
            if state.findings and state.phase in ("scan", "validate"):
                state.phase = "validate"
                self._update_tui("validate")
                await self._phase_validate(state)

        except Exception as exc:
            logger.error(f"Scan error: {exc}", exc_info=True)
            state.errors.append(str(exc))
            self._save_checkpoint(state)
        finally:
            state.phase = "complete"
            state.ended_at = datetime.utcnow()
            self._update_tui("complete")

            # End RL episode and log summary
            rl_summary = self.rl.end_episode()
            state.log_thought(
                f"RL episode: {rl_summary['steps']} steps, "
                f"total_reward={rl_summary['total_reward']:.3f}, "
                f"mean={rl_summary['mean_reward']:.3f}"
            )

            if self.memory:
                self.memory.store_findings(state.scan_id, state.findings)
                self.memory.finish_scan(state.scan_id, {
                    **state.stats(),
                    "total_score": self.reward.total_score,
                }, reward_data=self.reward.to_dict())

            self._remove_checkpoint()

        return state

    # ── Phase: Pre-Engagement Gate ────────────────────────────

    async def _phase_pre_engagement(self, state: ScanState) -> bool:
        """
        Phase 0: Run the pre-engagement checklist before any network traffic.
        Returns True if scan may proceed, False if scan must abort.

        Enforcement rules:
          IF target NOT in_scope_assets → Abort
          IF vulnerability_type IN scope_exclusions → Abort
          IF automated_scanning_restrictions == true → Disable mass scan modules
          IF safe_harbor_clause_present == false → Flag high legal risk
        """
        state.log_thought("Running pre-engagement gate checks")

        # Determine the checklist source
        checklist = self._pre_engagement_checklist
        gate = None

        if checklist:
            # Standalone checklist provided
            gate = PreEngagementGate(checklist)
            scope_domains = (
                checklist.in_scope_domains
                or (self.target.scope.allowed_domains if self.target.scope else [])
            )
            oos_domains = checklist.oos_domains
        elif self.policy_enforcer:
            # Policy-based: delegate to PolicyEnforcer which wraps the gate
            issues = self.policy_enforcer.pre_scan_check(
                self.target.url,
                requested_modules=self.modules,
            )
            result = self.policy_enforcer.pre_engagement_result

            if result:
                self._pre_engagement_result = result
                # Print gate results
                try:
                    print_pre_engagement_banner(result)
                except Exception:
                    print(result.summary())

                # Apply enforcements
                self._apply_gate_enforcements(result, state)

                # Log all issues
                for issue in issues:
                    state.log_thought(f"Policy: {issue}")

                if self.policy_enforcer.should_abort():
                    for reason in result.abort_reasons:
                        state.errors.append(f"PRE-ENGAGEMENT ABORT: {reason}")
                    return False

                # Interactive confirmation prompt
                if not self._confirm_scan(result, state):
                    return False

                return True
            else:
                # Fallback: legacy pre_scan_check without gate result
                for issue in issues:
                    state.log_thought(f"Policy: {issue}")
                    if issue.startswith("CRITICAL"):
                        state.errors.append(issue)
                        return False
                return True
        else:
            # No policy or checklist — run with basic scope check only
            state.log_thought("No policy/checklist configured — skipping pre-engagement gate")
            return True

        # Run standalone gate
        scope_domains = scope_domains or []
        oos = oos_domains or []
        result = gate.run_checks(
            target_url=self.target.url,
            in_scope_domains=scope_domains,
            oos_domains=oos,
            requested_modules=self.modules,
        )
        self._pre_engagement_result = result

        # Print gate results
        try:
            print_pre_engagement_banner(result)
        except Exception:
            print(result.summary())

        # Apply enforcements
        self._apply_gate_enforcements(result, state)

        if not result.passed:
            for reason in result.abort_reasons:
                state.errors.append(f"PRE-ENGAGEMENT ABORT: {reason}")
            return False

        # Interactive confirmation prompt
        if not self._confirm_scan(result, state):
            return False

        state.log_thought(f"Pre-engagement gate PASSED (legal risk: {result.legal_risk})")
        return True

    def _apply_gate_enforcements(self, result: PreEngagementResult, state: ScanState) -> None:
        """Apply enforcement decisions from the pre-engagement gate."""
        # Remove disabled modules
        if result.disabled_modules:
            original_count = len(self.modules)
            self.modules = [m for m in self.modules if m not in result.disabled_modules]
            removed = original_count - len(self.modules)
            if removed > 0:
                state.log_thought(
                    f"Pre-engagement: disabled {removed} modules: "
                    f"{', '.join(result.disabled_modules)}"
                )
                self._tui_thought(f"Disabled {removed} modules per policy")

        # Enforce rate limit
        if result.enforced_rate_limit and self._client:
            delay = 1.0 / result.enforced_rate_limit
            self._client._rate_limiter._delay = delay
            state.log_thought(
                f"Pre-engagement: rate limit set to {result.enforced_rate_limit} req/s"
            )

        # Store legal risk warning
        if result.legal_risk in ("medium", "high"):
            state.log_thought(
                f"⚠️  Legal risk: {result.legal_risk.upper()} — extra caution required"
            )

        # Propagate cloud-metadata filtering to scanner state
        if self.policy_enforcer and self.policy_enforcer.should_filter_cloud_payloads():
            state.target.metadata["filter_cloud_payloads"] = True
            state.log_thought("Pre-engagement: cloud-metadata payloads will be filtered")

    def _confirm_scan(self, result: PreEngagementResult, state: ScanState) -> bool:
        """
        Interactive confirmation prompt before scanning.
        Shows warnings/enforcements and asks user to confirm.
        Skipped when auto_confirm=True or --yes flag is used.
        """
        if self.auto_confirm:
            state.log_thought("Auto-confirm enabled — proceeding without prompt")
            return True

        # Only prompt if there are warnings, legal risk, or disabled modules
        has_warnings = bool(result.warnings) or result.legal_risk != "low"
        has_enforcements = bool(result.disabled_modules) or result.enforced_rate_limit
        if not has_warnings and not has_enforcements:
            return True

        try:
            from rich.console import Console
            console = Console()

            console.print("\n[bold yellow]⚠️  Pre-Scan Safety Confirmation[/]")
            console.print(f"   Target : [cyan]{self.target.url}[/]")
            console.print(f"   Modules: [cyan]{len(self.modules)}[/] active")

            if result.warnings:
                console.print(f"   Warnings: [yellow]{len(result.warnings)}[/]")
                for w in result.warnings:
                    console.print(f"     [yellow]• {w}[/]")

            if result.disabled_modules:
                console.print(
                    f"   Disabled: [red]{', '.join(result.disabled_modules)}[/]"
                )
            if result.enforced_rate_limit:
                console.print(f"   Rate Limit: [cyan]{result.enforced_rate_limit} req/s[/]")

            risk_color = {"low": "green", "medium": "yellow", "high": "red"}
            console.print(
                f"   Legal Risk: [{risk_color.get(result.legal_risk, 'white')}]"
                f"{result.legal_risk.upper()}[/]"
            )

            console.print()
            answer = input("   Proceed with scan? [y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                state.log_thought("User declined to proceed after pre-engagement check")
                state.errors.append("ABORTED: User declined confirmation prompt")
                console.print("[bold red]   Scan aborted by user.[/]\n")
                return False
            console.print("[green]   Confirmed — starting scan.[/]\n")
            return True

        except (ImportError, EOFError, KeyboardInterrupt):
            # Non-interactive mode or no rich — prompt with plain text
            try:
                print(f"\n   Pre-Scan Confirmation: {len(result.warnings)} warnings, "
                      f"legal risk: {result.legal_risk.upper()}")
                answer = input("   Proceed with scan? [y/N] ").strip().lower()
                if answer not in ("y", "yes"):
                    state.log_thought("User declined to proceed")
                    state.errors.append("ABORTED: User declined confirmation prompt")
                    return False
                return True
            except (EOFError, KeyboardInterrupt):
                # Non-interactive: fail-closed when legal risk or warnings exist
                if result.legal_risk != "low" or result.warnings:
                    state.log_thought(
                        "Non-interactive — aborting (legal risk or warnings present)"
                    )
                    state.errors.append(
                        "ABORTED: Non-interactive mode with legal risk/warnings — "
                        "use --yes to auto-confirm"
                    )
                    return False
                state.log_thought("Non-interactive — auto-confirming (no warnings)")
                return True

    # ── Phase: Recon ──────────────────────────────────────────

    async def _phase_recon(self, state):
        state.log_thought("Starting reconnaissance")
        resp, _ = await self._client.get(self.target.url)
        if resp:
            fp = Fingerprinter().analyse(resp)
            self.target.technologies = fp.get("technologies", [])
            self.target.headers = fp.get("interesting_headers", {})
            self.target.metadata.update(fp)
            state.log_thought(f"Technologies: {self.target.technologies}")
            self._tui_thought(f"Identified: {', '.join(self.target.technologies[:5])}")

        # WAF Detection
        waf_name = await self.waf.detect(self._client, self.target.url)
        if waf_name:
            state.log_thought(f"WAF detected: {waf_name}")
            self._tui_thought(f"WAF: {waf_name} -- bypass mode active")
            self.target.metadata["waf"] = waf_name
        else:
            state.log_thought("No WAF detected")

        self.target = await Crawler(self._client).crawl(self.target)
        state.target = self.target
        state.log_thought(f"Crawled {len(self.target.discovered_urls)} URLs")
        self._tui_thought(f"Crawled {len(self.target.discovered_urls)} URLs, "
                          f"{len(self.target.discovered_params)} parameterised endpoints")

        self.reward.score_recon(self.target.technologies, len(self.target.discovered_urls))
        self._update_tui_score()

    # ── Phase: Strategy ───────────────────────────────────────

    async def _phase_strategy(self, state):
        state.log_thought("Analysing recon for strategy")
        try:
            reward_ctx = self.reward.to_ai_context()
            memory_ctx = self.memory.to_ai_context(self.target.url) if self.memory else ""

            strategy = await self.ai.analyse_recon(state.target, reward_ctx, memory_ctx)
            prio = strategy.get("priority_modules", [])
            reasoning = strategy.get("reasoning", "")
            source = strategy.get("source", "unknown")

            all_mods = list(self.modules)
            ai_ordered = [m for m in prio if m in all_mods] + [m for m in all_mods if m not in prio]
            rl_ordered = self.rl.rank_modules(
                ai_ordered,
                technologies=self.target.technologies,
                preferred_order=ai_ordered,
            )
            state.modules_pending = rl_ordered

            if reasoning:
                state.log_thought(f"Strategy ({source}): {reasoning[:200]}")
                self._tui_thought(f"[{source}] {reasoning[:100]}")

            state.log_thought(f"AI module priority: {ai_ordered[:5]}")
            state.log_thought(f"RL module priority: {rl_ordered[:5]}")
            state.log_thought(f"RL policy: {self.rl.summary()}")

        except Exception as exc:
            logger.warning(f"Strategy phase error: {exc}")
            state.modules_pending = list(self.modules)

    # ── Phase: Scanning ───────────────────────────────────────

    async def _phase_scan(self, state):
        if not state.modules_pending:
            state.modules_pending = list(self.modules)

        # Filter out modules disabled by pre-engagement gate
        if self._pre_engagement_result and self._pre_engagement_result.disabled_modules:
            disabled = set(self._pre_engagement_result.disabled_modules)
            before = len(state.modules_pending)
            state.modules_pending = [m for m in state.modules_pending if m not in disabled]
            if len(state.modules_pending) < before:
                state.log_thought(
                    f"Policy: filtered {before - len(state.modules_pending)} disabled modules"
                )

        scanner_pairs = [(n, load_scanner(n)) for n in state.modules_pending]
        scanner_pairs = [(n, c) for n, c in scanner_pairs if c]
        scanner_map = {name: cls for name, cls in scanner_pairs}

        known = self.memory.get_known_findings(self.target.url) if self.memory else set()
        known = set(known)

        total_modules = len(scanner_pairs)
        if self._tui:
            self._tui.start_module("Scanning", total=total_modules * 100)

        remaining = [name for name, _ in scanner_pairs]
        while remaining:
            # Build RL environment state for state-aware action selection
            env_state = self._build_env_state(state, remaining)
            name = self.rl.choose_action(
                available_modules=remaining,
                technologies=self.target.technologies,
                env_state=env_state,
            )
            cls = scanner_map[name]
            scanner = cls(self._client)
            self._tui_thought(f"RL selected: {name} (strategy={self.rl.exploration_strategy_name})")
            remaining.remove(name)

            try:
                await scanner.setup()
                findings = await asyncio.wait_for(
                    scanner.run(state), timeout=SCAN_TIMEOUT_PER_MODULE
                )
                state.modules_run.append(name)

                findings = findings or []

                # Existing reward + learning
                self.reward.score_scanner_results(name, findings, known)
                ai_consulted = self.ai.learn_scan_results(
                    self.target.technologies, name, bool(findings)
                )

                # ── Confidence-aware reward computation ───────
                rl_reward = self._compute_rl_module_reward(findings, known)
                findings_data = self._build_findings_data(findings, known)
                abstained = (len(findings) == 0)

                # Check if AI was consulted (= "asked to learn")
                asked_to_learn = bool(ai_consulted)
                if asked_to_learn:
                    vuln_types = list({f.vuln_type for f in findings if f.vuln_type})
                    self.rl.reward_interpreter.teaching_memory.record_teaching(name, vuln_types)

                # Check for delayed teaching bonus
                finding_vuln_types = [f.vuln_type for f in findings if f.confirmed]
                taught_hits = self.rl.reward_interpreter.teaching_memory.check_taught_hits(
                    name, finding_vuln_types, ai_assisted=asked_to_learn,
                )

                next_env_state = self._build_env_state(state, remaining)
                is_last = len(remaining) == 0
                shaped = self.rl.observe(
                    name, rl_reward,
                    technologies=self.target.technologies,
                    next_env_state=next_env_state,
                    done=is_last,
                    findings_data=findings_data if findings_data else None,
                    abstained=abstained,
                    asked_to_learn=asked_to_learn,
                    taught_topics_hit=taught_hits,
                )
                self._module_rewards[name] = rl_reward

                breakdown = self.rl.reward_interpreter._last_breakdown
                breakdown_str = " ".join(f"{k}={v}" for k, v in breakdown.items()) if breakdown else "raw"
                state.log_thought(
                    f"RL update: {name} raw={rl_reward:+.2f} shaped={shaped:+.2f} "
                    f"[{breakdown_str}] | {self.rl.summary(3)}"
                )

                self._update_tui_score()

                for f in findings:
                    state.add_finding(f)
                    if self._tui:
                        self._tui.add_finding(f.title, f.severity, f.url, name)

                if self._tui:
                    self._tui.complete_module("Scanning")

            except asyncio.TimeoutError:
                state.errors.append(f"{name}: timeout after {SCAN_TIMEOUT_PER_MODULE}s")
                self.reward.record("no_progress_action", module=name)
                next_env = self._build_env_state(state, remaining)
                self.rl.observe(name, -1.0, technologies=self.target.technologies,
                               next_env_state=next_env, done=len(remaining) == 0)
                self._module_rewards[name] = -1.0
                state.log_thought(f"RL update: {name} reward=-1.00 (timeout)")
            except Exception as exc:
                state.errors.append(f"{name}: {exc}")
                self.reward.record("incorrect_exploit_attempt", module=name,
                                   detail=str(exc))
                next_env = self._build_env_state(state, remaining)
                self.rl.observe(name, -1.0, technologies=self.target.technologies,
                               next_env_state=next_env, done=len(remaining) == 0)
                self._module_rewards[name] = -1.0
                state.log_thought(f"RL update: {name} reward=-1.00 (error)")
            finally:
                try:
                    await scanner.teardown()
                except Exception:
                    pass

        state.log_thought(f"Raw findings: {len(state.findings)}")
        self._tui_thought(f"Scan complete: {len(state.findings)} raw findings")

    def _compute_rl_module_reward(self, findings, known: set) -> float:
        """Compute per-module reward signal for online RL updates."""
        if not findings:
            return float(self.rl_reward_map.get("no_progress_action", -5)) / 10.0

        reward = 0.0
        for finding in findings:
            key = (finding.url, finding.parameter, finding.vuln_type)
            if key in known:
                reward += float(self.rl_reward_map.get("duplicate_finding", -30)) / 100.0
                continue

            known.add(key)

            # Compute confidence score from VALIDATION_RULES or evidence heuristic
            finding.confidence = self._estimate_confidence(finding)

            if finding.confirmed:
                reward += float(self.rl_reward_map.get("confirmed_finding", 50)) / 100.0
                reward += float(self.rl_reward_map.get("successful_exploit", 100)) / 200.0
            else:
                reward += 0.4

            sev = (finding.severity or "").lower()
            if sev == "critical":
                reward += float(self.rl_reward_map.get("critical_severity_found", 80)) / 100.0
            elif sev == "high":
                reward += float(self.rl_reward_map.get("high_severity_found", 40)) / 100.0
            elif sev == "medium":
                reward += 0.2

        return reward

    def _estimate_confidence(self, finding) -> float:
        """
        Estimate the agent's confidence in a finding.

        Sources (checked in priority order):
          1. finding.confidence if already set (e.g., by scanner)
          2. VALIDATION_RULES base_confidence (heuristic per vuln type)
          3. Evidence-length heuristic for unknown vuln types

        Returns float in [0.0, 1.0].
        """
        if finding.confidence > 0.0:
            return min(finding.confidence, 1.0)

        # Check VALIDATION_RULES
        from core.ai_brain import VALIDATION_RULES
        rules = VALIDATION_RULES.get(finding.vuln_type)
        if rules:
            base = rules["base_confidence"] / 100.0  # convert 0-100 → 0.0-1.0
            # Boost confidence if the confirmation predicate passes
            if rules["confirmed_if"](finding):
                return min(base + 0.1, 1.0)
            return max(base - 0.1, 0.0)

        # Fallback: evidence-based heuristic
        evidence_len = len(finding.evidence or "")
        if evidence_len > 200:
            return 0.7
        elif evidence_len > 50:
            return 0.5
        return 0.3

    def _build_findings_data(self, findings, known: set) -> list:
        """
        Build the findings_data list for the confidence-aware reward function.

        Each entry: {"correct": bool, "confidence": float}
        "correct" = confirmed AND not a duplicate AND not false_positive.
        """
        data = []
        seen = set()
        for f in findings:
            key = (f.url, f.parameter, f.vuln_type)
            if key in seen:
                continue  # skip duplicates within this batch
            seen.add(key)

            correct = f.confirmed and not f.false_positive
            confidence = f.confidence if f.confidence > 0.0 else self._estimate_confidence(f)
            data.append({"correct": correct, "confidence": confidence})
        return data

    # ── Phase: Validation ─────────────────────────────────────

    async def _phase_validate(self, state):
        state.log_thought("Validating findings")

        # Filter out findings for excluded vuln types (per policy)
        if self.policy_enforcer:
            before_count = len(state.findings)
            state.findings = self.policy_enforcer.filter_findings(state.findings)
            filtered = before_count - len(state.findings)
            if filtered > 0:
                state.log_thought(f"Policy: filtered {filtered} out-of-scope finding(s)")

        validated = []
        for finding in state.findings:
            try:
                finding = await self.ai.validate_finding(finding)
                if not finding.false_positive:
                    if finding.confirmed and not finding.poc_steps:
                        finding.poc_steps = await self.ai.generate_poc(finding)
                    validated.append(finding)

                    if finding.confirmed:
                        self.reward.record("successful_exploit", module=finding.module,
                                           target_url=finding.url, detail=finding.title)
                        self._update_tui_score()
                else:
                    self.reward.record("incorrect_exploit_attempt", module=finding.module,
                                       target_url=finding.url, detail=f"FP: {finding.title}")
            except Exception:
                validated.append(finding)

        state.findings = validated
        confirmed_count = sum(1 for f in state.findings if f.confirmed)
        state.log_thought(f"Confirmed: {confirmed_count}/{len(state.findings)}")
        self._tui_thought(f"Validated: {confirmed_count} confirmed, "
                          f"{len(state.findings) - confirmed_count} unconfirmed")

    # ── Report ────────────────────────────────────────────────

    async def generate_report(self, state: ScanState) -> str:
        reward_summary = self.reward.to_ai_context()
        return await self.ai.summarise_scan(state, reward_summary)

    # ── Checkpoint / Resume ───────────────────────────────────

    def _save_checkpoint(self, state: ScanState) -> None:
        try:
            data = {
                "scan_id": state.scan_id,
                "phase": state.phase,
                "target_url": state.target.url,
                "modules_run": state.modules_run,
                "modules_pending": state.modules_pending,
                "findings_count": len(state.findings),
                "errors": state.errors,
                "thoughts": state.agent_thoughts,
                "reward": self.reward.to_dict(),
                "timestamp": datetime.utcnow().isoformat(),
            }
            with open(CHECKPOINT_FILE, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as exc:
            logger.debug(f"Checkpoint save failed: {exc}")

    def _load_checkpoint(self, state: ScanState, checkpoint_path: str) -> ScanState:
        try:
            with open(checkpoint_path) as f:
                data = json.load(f)
            state.phase = data.get("phase", "init")
            state.modules_run = data.get("modules_run", [])
            state.modules_pending = data.get("modules_pending", [])
            state.errors = data.get("errors", [])
            state.agent_thoughts = data.get("thoughts", [])
            if "reward" in data:
                self.reward = RewardEngine.from_dict(data["reward"])
            state.log_thought(f"Resumed from checkpoint (phase: {state.phase})")
            logger.info(f"Scan resumed from phase: {state.phase}")
        except Exception as exc:
            logger.warning(f"Could not load checkpoint: {exc}")
        return state

    def _remove_checkpoint(self) -> None:
        try:
            if os.path.exists(CHECKPOINT_FILE):
                os.remove(CHECKPOINT_FILE)
        except Exception:
            pass

    # ── TUI Helpers ───────────────────────────────────────────

    def _update_tui(self, phase: str) -> None:
        if self._tui:
            self._tui.update_phase(phase)

    def _update_tui_score(self) -> None:
        if self._tui:
            self._tui.update_score(self.reward.total_score)

    def _tui_thought(self, thought: str) -> None:
        if self._tui:
            self._tui.add_thought(thought)
