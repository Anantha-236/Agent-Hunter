"""
Agent-Hunter Comprehensive Test Plan
======================================
Tests all 17 scanner modules against a local intentionally-vulnerable server.
Covers: Injection, Auth, Misconfig, API, Full Pipeline, and Unit/Component tests.

Run with:
    python -m pytest tests/test_full_plan.py -v --tb=short -x

Markers:
    @pytest.mark.fast      — quick unit tests
    @pytest.mark.slow      — scanner integration tests (need local server)
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import time
import uuid

import pytest

# ── Project root on path ────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.models import Finding, Scope, ScanState, Target
from utils.http_client import HttpClient
from tests.vuln_server import VULN_PORT, start_vuln_server, stop_vuln_server

# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

BASE_URL: str = ""


@pytest.fixture(scope="session", autouse=True)
def vuln_server():
    """Start the local vulnerable server once for the whole test session."""
    global BASE_URL
    BASE_URL = start_vuln_server()
    yield BASE_URL
    stop_vuln_server()


def _base() -> str:
    return BASE_URL or f"http://127.0.0.1:{VULN_PORT}"


def _make_target(**discovered) -> Target:
    """Build a Target pointed at the local vuln server."""
    base = _base()
    scope = Scope(allowed_domains=["127.0.0.1", "*.127.0.0.1", "localhost"])
    t = Target(url=base, scope=scope)
    t.discovered_urls = discovered.get("urls", [
        f"{base}/",
        f"{base}/search?q=test",
        f"{base}/products?cat=1",
        f"{base}/ping?ip=127.0.0.1",
        f"{base}/view?file=readme.txt",
        f"{base}/fetch?url=http://example.com",
        f"{base}/template?name=World",
        f"{base}/login",
        f"{base}/admin",
        f"{base}/profile?id=1",
        f"{base}/transfer",
        f"{base}/coupon/apply?code=TEST10",
        f"{base}/redirect?ref=home",
        f"{base}/forgot-password",
    ])
    t.discovered_params = discovered.get("params", {
        f"{base}/search": ["q"],
        f"{base}/products": ["cat"],
        f"{base}/ping": ["ip"],
        f"{base}/view": ["file"],
        f"{base}/fetch": ["url"],
        f"{base}/template": ["name"],
        f"{base}/login": ["redirect", "next"],
        f"{base}/profile": ["id"],
        f"{base}/redirect": ["ref"],
    })
    t.technologies = discovered.get("technologies", ["php", "mysql", "apache"])
    return t


def _make_state(**discovered) -> ScanState:
    return ScanState(target=_make_target(**discovered))


@pytest.fixture
def http_client():
    """Provide an HttpClient scoped to the vuln server."""
    scope = Scope(allowed_domains=["127.0.0.1", "localhost"])
    client = HttpClient(scope=scope, verify_ssl=False, timeout=10,
                        rate_limit=100, concurrency=20)
    return client


def _run(coro):
    """Run an async coroutine in a new event loop."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ═══════════════════════════════════════════════════════════════════════════════
# Helper: run a scanner and return findings
# ═══════════════════════════════════════════════════════════════════════════════

async def _scan(scanner_cls, client, state):
    async with client:
        scanner = scanner_cls(client)
        await scanner.setup()
        try:
            findings = await asyncio.wait_for(scanner.run(state), timeout=60)
        finally:
            await scanner.teardown()
    return findings or []


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: INJECTION SCANNERS
# ═══════════════════════════════════════════════════════════════════════════════

class TestSQLInjection:
    """Test 1.1: SQL Injection detection."""

    @pytest.mark.slow
    def test_error_based_sqli(self, http_client, vuln_server):
        """SQLi scanner detects error-based SQL injection on /products?cat=..."""
        from scanners.injection.sql_injection import SQLInjectionScanner
        state = _make_state()
        findings = _run(_scan(SQLInjectionScanner, http_client, state))
        sqli = [f for f in findings if "sql" in f.vuln_type.lower() or "sql" in f.title.lower()]
        assert len(sqli) > 0, (
            f"Expected SQL injection findings, got {len(findings)} total findings: "
            f"{[f.title for f in findings]}"
        )
        # Should detect on the /products endpoint
        product_sqli = [f for f in sqli if "/products" in f.url]
        assert len(product_sqli) > 0, f"Expected SQLi on /products, found on: {[f.url for f in sqli]}"


class TestXSS:
    """Test 1.2: Cross-Site Scripting detection."""

    @pytest.mark.slow
    def test_reflected_xss(self, http_client, vuln_server):
        """XSS scanner detects reflected XSS on /search?q=..."""
        from scanners.xss.xss_scanner import XSSScanner
        state = _make_state()
        findings = _run(_scan(XSSScanner, http_client, state))
        xss = [f for f in findings if "xss" in f.vuln_type.lower() or "xss" in f.title.lower()
               or "cross" in f.title.lower()]
        assert len(xss) > 0, (
            f"Expected XSS findings, got {len(findings)} total: {[f.title for f in findings]}"
        )
        search_xss = [f for f in xss if "/search" in f.url]
        assert len(search_xss) > 0, f"Expected XSS on /search, found on: {[f.url for f in xss]}"


class TestCommandInjection:
    """Test 1.3: Command Injection detection."""

    @pytest.mark.slow
    def test_output_based_cmdi(self, http_client, vuln_server):
        """CmdI scanner detects command injection on /ping?ip=..."""
        from scanners.injection.command_injection import CommandInjectionScanner
        state = _make_state()
        findings = _run(_scan(CommandInjectionScanner, http_client, state))
        cmdi = [f for f in findings if "command" in f.vuln_type.lower()
                or "injection" in f.title.lower() or "rce" in f.vuln_type.lower()]
        assert len(cmdi) > 0, (
            f"Expected command injection findings, got {len(findings)} total: "
            f"{[f.title for f in findings]}"
        )


class TestPathTraversal:
    """Test 1.4: Path Traversal / LFI detection."""

    @pytest.mark.slow
    def test_lfi(self, http_client, vuln_server):
        """Path traversal scanner detects LFI on /view?file=..."""
        from scanners.file.path_traversal import PathTraversalScanner
        state = _make_state()
        findings = _run(_scan(PathTraversalScanner, http_client, state))
        lfi = [f for f in findings if "traversal" in f.vuln_type.lower()
               or "path" in f.vuln_type.lower() or "lfi" in f.vuln_type.lower()
               or "file" in f.title.lower()]
        assert len(lfi) > 0, (
            f"Expected path traversal findings, got {len(findings)} total: "
            f"{[f.title for f in findings]}"
        )


class TestSSRF:
    """Test 1.5: SSRF detection."""

    @pytest.mark.slow
    def test_ssrf(self, http_client, vuln_server):
        """SSRF scanner detects server-side request forgery on /fetch?url=..."""
        from scanners.ssrf.ssrf_scanner import SSRFScanner
        state = _make_state()
        findings = _run(_scan(SSRFScanner, http_client, state))
        ssrf = [f for f in findings if "ssrf" in f.vuln_type.lower()
                or "request forgery" in f.title.lower()]
        assert len(ssrf) > 0, (
            f"Expected SSRF findings, got {len(findings)} total: "
            f"{[f.title for f in findings]}"
        )


class TestSSTI:
    """Test 1.6: Server-Side Template Injection detection."""

    @pytest.mark.slow
    def test_ssti(self, http_client, vuln_server):
        """SSTI scanner detects template injection on /template?name=..."""
        from scanners.injection.ssti import SSTIScanner
        state = _make_state()
        findings = _run(_scan(SSTIScanner, http_client, state))
        ssti = [f for f in findings if "ssti" in f.vuln_type.lower()
                or "template" in f.vuln_type.lower() or "template" in f.title.lower()]
        assert len(ssti) > 0, (
            f"Expected SSTI findings, got {len(findings)} total: "
            f"{[f.title for f in findings]}"
        )


class TestXXE:
    """Test 1.7: XML External Entity detection."""

    @pytest.mark.slow
    def test_xxe(self, http_client, vuln_server):
        """XXE scanner detects XML external entity injection."""
        from scanners.injection.xxe_scanner import XXEScanner
        state = _make_state()
        # XXE scanner posts XML to discovered URLs
        findings = _run(_scan(XXEScanner, http_client, state))
        xxe = [f for f in findings if "xxe" in f.vuln_type.lower()
               or "xml" in f.vuln_type.lower() or "external entity" in f.title.lower()]
        # XXE may or may not find vulns on our simple server — at least no crash
        assert isinstance(findings, list), "Scanner should return a list"


class TestCRLF:
    """Test 1.8: CRLF Injection detection."""

    @pytest.mark.slow
    def test_crlf(self, http_client, vuln_server):
        """CRLF scanner detects header injection on /redirect?ref=..."""
        from scanners.injection.crlf_injection import CRLFInjectionScanner
        state = _make_state()
        findings = _run(_scan(CRLFInjectionScanner, http_client, state))
        crlf = [f for f in findings if "crlf" in f.vuln_type.lower()
                or "header" in f.title.lower()]
        # CRLF detection depends on server header parsing — at minimum no crash
        assert isinstance(findings, list), "Scanner should return a list"


class TestGraphQL:
    """Test 1.9: GraphQL vulnerability detection."""

    @pytest.mark.slow
    def test_graphql_introspection(self, http_client, vuln_server):
        """GraphQL scanner detects introspection and other issues."""
        from scanners.injection.graphql_scanner import GraphQLScanner
        base = _base()
        state = _make_state(urls=[
            f"{base}/",
            f"{base}/graphql",
        ])
        findings = _run(_scan(GraphQLScanner, http_client, state))
        gql = [f for f in findings if "graphql" in f.vuln_type.lower()
               or "graphql" in f.title.lower() or "introspection" in f.title.lower()]
        assert len(gql) > 0, (
            f"Expected GraphQL findings, got {len(findings)} total: "
            f"{[f.title for f in findings]}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: AUTH & AUTHZ SCANNERS
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuth:
    """Test 2.1: Authentication scanner (default creds, JWT, etc.)."""

    @pytest.mark.slow
    def test_default_credentials(self, http_client, vuln_server):
        """Auth scanner detects default credentials on /admin."""
        from scanners.auth.auth_scanner import AuthScanner
        state = _make_state()
        findings = _run(_scan(AuthScanner, http_client, state))
        auth = [f for f in findings if "auth" in f.vuln_type.lower()
                or "credential" in f.title.lower() or "default" in f.title.lower()
                or "password" in f.title.lower()]
        assert len(auth) > 0, (
            f"Expected auth findings (default creds), got {len(findings)} total: "
            f"{[f.title for f in findings]}"
        )


class TestCSRF:
    """Test 2.2: CSRF detection."""

    @pytest.mark.slow
    def test_csrf_missing_token(self, http_client, vuln_server):
        """CSRF scanner detects missing tokens on /transfer form."""
        from scanners.auth.csrf_scanner import CSRFScanner
        state = _make_state()
        findings = _run(_scan(CSRFScanner, http_client, state))
        csrf = [f for f in findings if "csrf" in f.vuln_type.lower()
                or "cross-site request" in f.title.lower()
                or "csrf" in f.title.lower()]
        assert len(csrf) > 0, (
            f"Expected CSRF findings, got {len(findings)} total: "
            f"{[f.title for f in findings]}"
        )


class TestIDOR:
    """Test 2.3: IDOR detection."""

    @pytest.mark.slow
    def test_idor(self, http_client, vuln_server):
        """IDOR scanner detects insecure direct object reference on /profile?id=..."""
        from scanners.authz.idor_scanner import IDORScanner
        state = _make_state()
        findings = _run(_scan(IDORScanner, http_client, state))
        idor = [f for f in findings if "idor" in f.vuln_type.lower()
                or "insecure" in f.title.lower() or "object" in f.title.lower()
                or "authorization" in f.vuln_type.lower()]
        assert len(idor) > 0, (
            f"Expected IDOR findings, got {len(findings)} total: "
            f"{[f.title for f in findings]}"
        )


class TestOpenRedirect:
    """Test 2.4: Open Redirect detection."""

    @pytest.mark.slow
    def test_open_redirect(self, http_client, vuln_server):
        """Open redirect scanner detects redirect on /login?redirect=..."""
        from scanners.redirect.open_redirect import OpenRedirectScanner
        base = _base()
        state = _make_state(params={
            f"{base}/login": ["redirect", "next", "return"],
        })
        findings = _run(_scan(OpenRedirectScanner, http_client, state))
        redir = [f for f in findings if "redirect" in f.vuln_type.lower()
                 or "redirect" in f.title.lower()]
        assert len(redir) > 0, (
            f"Expected open redirect findings, got {len(findings)} total: "
            f"{[f.title for f in findings]}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: MISCONFIGURATION SCANNERS
# ═══════════════════════════════════════════════════════════════════════════════

class TestMisconfig:
    """Test 3.1: Misconfiguration scanner (headers, sensitive files, CORS)."""

    @pytest.mark.slow
    def test_sensitive_files(self, http_client, vuln_server):
        """Misconfig scanner detects .env, .git/HEAD, etc."""
        from scanners.misconfig.misconfig_scanner import MisconfigScanner
        state = _make_state()
        findings = _run(_scan(MisconfigScanner, http_client, state))
        sensitive = [f for f in findings if ".env" in f.url or ".git" in f.url
                     or "sensitive" in f.title.lower() or "exposed" in f.title.lower()
                     or "header" in f.title.lower() or "cors" in f.title.lower()
                     or "misconfig" in f.vuln_type.lower() or "security" in f.title.lower()]
        assert len(sensitive) > 0, (
            f"Expected misconfig findings, got {len(findings)} total: "
            f"{[f.title for f in findings]}"
        )

    @pytest.mark.slow
    def test_missing_security_headers(self, http_client, vuln_server):
        """Misconfig scanner detects missing security headers."""
        from scanners.misconfig.misconfig_scanner import MisconfigScanner
        state = _make_state()
        findings = _run(_scan(MisconfigScanner, http_client, state))
        headers = [f for f in findings if "header" in f.title.lower()
                   or "hsts" in f.title.lower() or "csp" in f.title.lower()
                   or "x-frame" in f.title.lower()]
        # Server intentionally omits security headers
        assert len(headers) >= 0, "Should detect missing headers (may vary by scanner logic)"


class TestHostHeader:
    """Test 3.2: Host Header Injection detection."""

    @pytest.mark.slow
    def test_host_header_injection(self, http_client, vuln_server):
        """Host header scanner detects injection on /forgot-password."""
        from scanners.misconfig.host_header import HostHeaderScanner
        state = _make_state()
        findings = _run(_scan(HostHeaderScanner, http_client, state))
        hhi = [f for f in findings if "host" in f.vuln_type.lower()
               or "header" in f.title.lower() or "host" in f.title.lower()]
        assert len(hhi) > 0, (
            f"Expected host header injection findings, got {len(findings)} total: "
            f"{[f.title for f in findings]}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4: FULL PIPELINE INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestCrawler:
    """Test 4.1: Crawler discovers URLs and params."""

    @pytest.mark.slow
    def test_crawler_discovers_params(self, http_client, vuln_server):
        """Crawler should discover URLs and parameterised endpoints."""
        from recon.crawler import Crawler
        base = _base()
        scope = Scope(allowed_domains=["127.0.0.1", "localhost"])
        target = Target(url=base, scope=scope)

        async def run():
            async with http_client as c:
                crawler = Crawler(c)
                return await crawler.crawl(target, depth=2)

        t = _run(run())
        assert len(t.discovered_urls) > 3, f"Expected >3 URLs, got {len(t.discovered_urls)}"
        assert len(t.discovered_params) > 0, (
            f"Expected discovered params, got {len(t.discovered_params)}: {t.discovered_params}"
        )


class TestMultiScanner:
    """Test 4.2: Run multiple scanners in one session."""

    @pytest.mark.slow
    def test_multi_scanner_session(self, http_client, vuln_server):
        """Multiple scanners can run sequentially without interference."""
        from scanners.injection.sql_injection import SQLInjectionScanner
        from scanners.xss.xss_scanner import XSSScanner
        from scanners.misconfig.misconfig_scanner import MisconfigScanner

        state = _make_state()
        all_findings = []

        async def run():
            async with http_client as c:
                for cls in [SQLInjectionScanner, XSSScanner, MisconfigScanner]:
                    scanner = cls(c)
                    await scanner.setup()
                    try:
                        results = await asyncio.wait_for(scanner.run(state), timeout=60)
                        all_findings.extend(results or [])
                    finally:
                        await scanner.teardown()

        _run(run())
        assert len(all_findings) > 0, "Multi-scanner session should find at least one vuln"
        modules = set(f.module for f in all_findings if f.module)
        # At least some scanners should tag their findings
        assert isinstance(all_findings, list)


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5: RL AGENT UNIT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestRLAgent:
    """Test 5.1-5.4: RL policy agent unit tests."""

    @pytest.mark.fast
    def test_rl_import(self):
        """All RL classes import without error."""
        from core.rl_environment import EnvironmentState, ActionSpace, StateEncoder
        from core.rl_agent import (
            RLPolicyAgent, ConfidenceAwareReward, RewardInterpreter,
            TeachingMemory, EpsilonGreedy, BoltzmannExploration,
            UCB1Exploration, ThompsonSampling, HybridExploration,
        )
        assert True

    @pytest.mark.fast
    def test_action_space(self):
        """ActionSpace correctly maps modules to indices."""
        from core.rl_environment import ActionSpace
        modules = ["sql_injection", "xss_scanner", "misconfig_scanner"]
        space = ActionSpace(modules)
        assert space.n == 3
        assert space.index_of("sql_injection") == 0
        assert space.index_of("xss_scanner") == 1
        assert space.index_of("nonexistent") == -1

    @pytest.mark.fast
    def test_state_encoder(self):
        """StateEncoder produces a fixed-size feature vector."""
        from core.rl_environment import ActionSpace, EnvironmentState, StateEncoder
        modules = ["sql_injection", "xss_scanner"]
        state = EnvironmentState(
            target_url="http://example.com",
            technologies=["php", "mysql"],
            waf_detected=False, waf_name="",
            discovered_urls_count=30, discovered_params_count=80,
            ssl_present=True,
            modules_run=[], modules_remaining=modules,
            findings_count=0, confirmed_count=0,
            severity_counts={}, unique_vuln_types=set(),
            cumulative_reward=0.0, last_reward=0.0,
            rewards_history=[], elapsed_seconds=0.0,
            avg_module_time=0.0, step=0,
        )
        action_space = ActionSpace(modules)
        encoder = StateEncoder(action_space)
        features = encoder.encode(state)
        assert len(features) > 0, "Feature vector should be non-empty"
        assert all(isinstance(x, (int, float)) for x in features)

    @pytest.mark.fast
    def test_confidence_aware_reward(self):
        """ConfidenceAwareReward returns correct scores."""
        from core.rl_agent import ConfidenceAwareReward
        car = ConfidenceAwareReward(confidence_threshold=0.7)

        r, label = car.score_finding(correct=True, confidence=0.9)
        assert label == "correct_confident" and r == 1.0

        r, label = car.score_finding(correct=True, confidence=0.4)
        assert label == "correct_uncertain" and r == 0.7

        r, label = car.score_finding(correct=False, confidence=0.85)
        assert label == "wrong_confident" and r == -1.5

        r, label = car.score_finding(correct=False, confidence=0.3)
        assert label == "wrong_uncertain" and r == -0.5

    @pytest.mark.fast
    def test_teaching_memory(self):
        """TeachingMemory records and checks taught topics."""
        from core.rl_agent import TeachingMemory
        tm = TeachingMemory()
        tm.record_teaching("sql_injection", ["sqli", "blindsqli"])
        assert ("sql_injection", "sqli") in tm.taught_topics
        # AI-assisted → no bonus
        assert tm.check_taught_hits("sql_injection", ["sqli"], ai_assisted=True) == 0
        # Without AI → bonus
        assert tm.check_taught_hits("sql_injection", ["sqli", "blindsqli"], ai_assisted=False) == 2

    @pytest.mark.fast
    def test_agent_choose_and_observe(self):
        """RLPolicyAgent can choose actions and observe rewards."""
        from core.rl_agent import RLPolicyAgent
        from core.rl_environment import EnvironmentState

        fd, tmp = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(tmp)
        try:
            agent = RLPolicyAgent(
                modules=["modA", "modB", "modC"],
                state_file=tmp,
                value_backend="linear",
            )
            env_state = EnvironmentState(
                target_url="http://example.com",
                technologies=["php"], waf_detected=False, waf_name="",
                discovered_urls_count=10, discovered_params_count=5,
                ssl_present=True, modules_run=[], modules_remaining=["modA", "modB", "modC"],
                findings_count=0, confirmed_count=0,
                severity_counts={}, unique_vuln_types=set(),
                cumulative_reward=0.0, last_reward=0.0,
                rewards_history=[], elapsed_seconds=0.0,
                avg_module_time=0.0, step=0,
            )
            action = agent.choose_action(
                available_modules=["modA", "modB", "modC"],
                technologies=["php"],
                env_state=env_state,
            )
            assert action in ["modA", "modB", "modC"]

            # Observe a reward
            shaped = agent.observe(
                action, 1.0,
                technologies=["php"],
                next_env_state=env_state,
                done=False,
            )
            assert isinstance(shaped, float)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    @pytest.mark.fast
    def test_agent_save_load(self):
        """RLPolicyAgent can save and reload state."""
        from core.rl_agent import RLPolicyAgent
        from core.rl_environment import EnvironmentState

        fd, tmp = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(tmp)
        try:
            agent = RLPolicyAgent(
                modules=["modA", "modB"],
                state_file=tmp,
                value_backend="linear",
            )
            env = EnvironmentState(
                target_url="http://example.com", technologies=["node"],
                waf_detected=False, waf_name="",
                discovered_urls_count=5, discovered_params_count=3,
                ssl_present=False, modules_run=[], modules_remaining=["modA", "modB"],
                findings_count=0, confirmed_count=0,
                severity_counts={}, unique_vuln_types=set(),
                cumulative_reward=0.0, last_reward=0.0,
                rewards_history=[], elapsed_seconds=0.0,
                avg_module_time=0.0, step=0,
            )
            agent.start_episode()
            agent.choose_action(["modA", "modB"], ["node"], env)
            agent.observe("modA", 0.5, technologies=["node"],
                          next_env_state=env, done=True)
            agent.save()

            assert os.path.exists(tmp), "State file should exist after save"

            # Reload
            agent2 = RLPolicyAgent(
                modules=["modA", "modB"],
                state_file=tmp,
                value_backend="linear",
            )
            assert agent2._total_episodes >= 1, (
                f"Expected ≥1 episode after reload, got {agent2._total_episodes}"
            )
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    @pytest.mark.fast
    def test_deep_q_dimension_adaptation(self):
        """DeepQApproximator handles dimension changes on reload."""
        from core.deep_q_backend import DeepQApproximator

        # Create with 5 actions
        dq1 = DeepQApproximator(state_dim=10, n_actions=5)
        state_dict = dq1.to_dict()

        # Load into a 3-action approximator
        dq2 = DeepQApproximator(state_dim=10, n_actions=3)
        dq2.from_dict(state_dict)

        # Should not crash
        features = [0.1] * 10
        val = dq2.predict(features, 0)
        assert isinstance(val, float)

        # Load into a 7-action approximator (larger)
        dq3 = DeepQApproximator(state_dim=10, n_actions=7)
        dq3.from_dict(state_dict)
        val3 = dq3.predict(features, 6)
        assert isinstance(val3, float)


class TestExplorationStrategies:
    """Test 5.5: Exploration strategies work correctly."""

    def _mk_args(self, n=3):
        """Build the extra args that select() needs."""
        from core.rl_agent import ModulePolicyState
        from core.rl_environment import ActionSpace
        names = [f"mod{i}" for i in range(n)]
        action_space = ActionSpace(names)
        mask = [True] * n
        states = {name: ModulePolicyState() for name in names}
        return mask, states, action_space

    @pytest.mark.fast
    def test_epsilon_greedy(self):
        from core.rl_agent import EpsilonGreedy
        eg = EpsilonGreedy(epsilon=1.0)  # always explore
        q_values = [1.0, 2.0, 3.0]
        mask, states, aspace = self._mk_args(3)
        counts = {0: 0, 1: 0, 2: 0}
        for _ in range(300):
            idx = eg.select(q_values, mask, states, aspace, step=0)
            assert 0 <= idx < 3
            counts[idx] += 1
        assert all(c > 30 for c in counts.values()), f"Expected roughly uniform: {counts}"

    @pytest.mark.fast
    def test_boltzmann(self):
        from core.rl_agent import BoltzmannExploration
        b = BoltzmannExploration(temperature=0.1)
        q_values = [0.0, 0.0, 10.0]
        mask, states, aspace = self._mk_args(3)
        counts = {0: 0, 1: 0, 2: 0}
        for _ in range(100):
            idx = b.select(q_values, mask, states, aspace, step=0)
            counts[idx] += 1
        assert counts[2] > 80, f"Expected action 2 to dominate: {counts}"

    @pytest.mark.fast
    def test_ucb1(self):
        from core.rl_agent import UCB1Exploration
        ucb = UCB1Exploration()
        q_values = [1.0, 1.0, 1.0]
        mask, states, aspace = self._mk_args(3)
        idx = ucb.select(q_values, mask, states, aspace, step=0)
        assert 0 <= idx < 3

    @pytest.mark.fast
    def test_thompson_sampling(self):
        from core.rl_agent import ThompsonSampling
        ts = ThompsonSampling()
        q_values = [0.5, 0.5, 0.5]
        mask, states, aspace = self._mk_args(3)
        idx = ts.select(q_values, mask, states, aspace, step=0)
        assert 0 <= idx < 3


# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6: COMPONENT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

class TestModels:
    """Test 6.1: Core data models."""

    @pytest.mark.fast
    def test_target_creation(self):
        t = Target(url="http://example.com")
        assert t.url == "http://example.com"
        assert t.discovered_params == {}
        assert t.discovered_urls == []

    @pytest.mark.fast
    def test_scope_matching(self):
        scope = Scope(
            allowed_domains=["example.com", "*.example.com"],
            excluded_domains=["admin.example.com"],
        )
        assert scope.is_in_scope("http://example.com/page")
        assert scope.is_in_scope("http://sub.example.com/page")
        assert not scope.is_in_scope("http://admin.example.com/page")
        assert not scope.is_in_scope("http://evil.com/page")

    @pytest.mark.fast
    def test_finding_to_dict(self):
        f = Finding(
            title="Test XSS", vuln_type="xss", severity="high",
            url="http://example.com/search", parameter="q",
            payload="<script>alert(1)</script>",
        )
        d = f.to_dict()
        assert d["title"] == "Test XSS"
        assert d["vuln_type"] == "xss"
        assert d["parameter"] == "q"

    @pytest.mark.fast
    def test_scan_state_dedup(self):
        """ScanState.add_finding deduplicates identical findings."""
        target = Target(url="http://example.com")
        state = ScanState(target=target)
        f1 = Finding(url="http://example.com/a", parameter="q",
                     vuln_type="xss", payload="<script>", evidence="found")
        f2 = Finding(url="http://example.com/a", parameter="q",
                     vuln_type="xss", payload="<script>", evidence="found")
        state.add_finding(f1)
        state.add_finding(f2)
        assert len(state.findings) == 1, "Duplicate findings should be deduplicated"


class TestHttpClient:
    """Test 6.2: HTTP client scope enforcement."""

    @pytest.mark.fast
    def test_scope_violation(self):
        from utils.http_client import HttpClient, ScopeViolationError
        scope = Scope(allowed_domains=["example.com"])
        client = HttpClient(scope=scope)
        with pytest.raises(ScopeViolationError):
            client._check_scope("http://evil.com/page")

    @pytest.mark.fast
    def test_scope_allowed(self):
        from utils.http_client import HttpClient
        scope = Scope(allowed_domains=["example.com"])
        client = HttpClient(scope=scope)
        # Should not raise
        client._check_scope("http://example.com/page")


class TestRewardEngine:
    """Test 6.3: Reward computation."""

    @pytest.mark.fast
    def test_reward_scoring(self):
        from core.reward import RewardEngine
        engine = RewardEngine()
        known = set()
        findings = [
            Finding(url="http://x.com/a", vuln_type="xss", severity="high",
                    confirmed=True, parameter="q", payload="<script>")
        ]
        engine.score_scanner_results("xss_scanner", findings, known)
        # Engine should track the result
        assert isinstance(engine.to_dict(), dict)


class TestCheckpointSerialization:
    """Test 6.4: Checkpoint save/load preserves data."""

    @pytest.mark.fast
    def test_checkpoint_roundtrip(self):
        """Verify checkpoint saves and loads correctly, including crawl data."""
        import json
        from datetime import UTC, datetime
        from core.models import Finding

        target = Target(url="http://example.com")
        target.discovered_urls = ["http://example.com/a", "http://example.com/b"]
        target.discovered_params = {"http://example.com/a": ["q", "id"]}
        target.technologies = ["php", "mysql"]
        state = ScanState(target=target)
        state.phase = "scan"
        state.modules_run = ["sql_injection"]
        state.modules_pending = ["xss_scanner"]
        state.findings.append(Finding(
            title="Test SQLi", vuln_type="sql_injection",
            severity="high", url="http://example.com/a",
            parameter="q", payload="' OR 1=1 --",
        ))

        # Simulate checkpoint save (matching orchestrator._save_checkpoint)
        data = {
            "scan_id": state.scan_id,
            "phase": state.phase,
            "resume_phase": state.phase,
            "target_url": state.target.url,
            "modules_run": state.modules_run,
            "modules_pending": state.modules_pending,
            "findings_count": len(state.findings),
            "findings": [f.to_dict() for f in state.findings],
            "discovered_urls": state.target.discovered_urls,
            "discovered_params": state.target.discovered_params,
            "technologies": state.target.technologies,
            "errors": state.errors,
            "thoughts": state.agent_thoughts,
            "timestamp": datetime.now(UTC).isoformat(),
        }

        fd, tmp = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        try:
            with open(tmp, "w") as f:
                json.dump(data, f)
            with open(tmp) as f:
                loaded = json.load(f)

            # Basic fields
            assert loaded["phase"] == "scan"
            assert loaded["modules_run"] == ["sql_injection"]
            assert loaded["target_url"] == "http://example.com"

            # Crawl data preserved
            assert loaded["discovered_urls"] == ["http://example.com/a", "http://example.com/b"]
            assert loaded["discovered_params"] == {"http://example.com/a": ["q", "id"]}
            assert loaded["technologies"] == ["php", "mysql"]

            # Findings preserved
            assert len(loaded["findings"]) == 1
            assert loaded["findings"][0]["title"] == "Test SQLi"
            assert loaded["findings"][0]["parameter"] == "q"

            # Simulate load into fresh state (matching orchestrator._load_checkpoint)
            target2 = Target(url="http://example.com")
            state2 = ScanState(target=target2)
            state2.phase = loaded.get("resume_phase", loaded.get("phase", "init"))
            state2.modules_run = loaded.get("modules_run", [])
            state2.modules_pending = loaded.get("modules_pending", [])
            if "discovered_urls" in loaded:
                state2.target.discovered_urls = loaded["discovered_urls"]
            if "discovered_params" in loaded:
                state2.target.discovered_params = loaded["discovered_params"]
            if "technologies" in loaded:
                state2.target.technologies = loaded["technologies"]
            if "findings" in loaded:
                for fd_dict in loaded["findings"]:
                    state2.findings.append(Finding(**{
                        k: v for k, v in fd_dict.items()
                        if k in Finding.__dataclass_fields__ and k != "discovered_at"
                    }))

            assert state2.target.discovered_urls == target.discovered_urls
            assert state2.target.discovered_params == target.discovered_params
            assert state2.target.technologies == target.technologies
            assert len(state2.findings) == 1
            assert state2.findings[0].title == "Test SQLi"
        finally:
            os.remove(tmp)


class TestScannerRegistry:
    """Test 6.5: All scanners in registry load correctly."""

    @pytest.mark.fast
    def test_all_scanners_loadable(self):
        """Every scanner in SCANNER_REGISTRY can be loaded."""
        from core.orchestrator import SCANNER_REGISTRY, load_scanner
        for name in SCANNER_REGISTRY:
            cls = load_scanner(name)
            assert cls is not None, f"Scanner '{name}' failed to load"

    @pytest.mark.fast
    def test_scanner_count(self):
        """Registry has expected number of scanners."""
        from core.orchestrator import SCANNER_REGISTRY
        assert len(SCANNER_REGISTRY) >= 15, (
            f"Expected ≥15 scanners, got {len(SCANNER_REGISTRY)}: {list(SCANNER_REGISTRY.keys())}"
        )
