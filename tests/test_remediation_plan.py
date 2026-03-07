import asyncio
from dataclasses import dataclass

import pytest

import api_server
import core.orchestrator as orchestrator_module
from core.models import Scope, Target
from recon import asset_discovery as asset_discovery_module
from recon.asset_discovery import AssetDiscovery, DiscoveredPort


def test_scope_restricts_urls_to_selected_assets_and_out_scope():
    scope = Scope(
        allowed_domains=["example.com", "*.example.com"],
        allowed_urls=["https://app.example.com/dashboard", "https://api.example.com/v1"],
        excluded_domains=["admin.example.com"],
    )

    assert scope.is_in_scope("https://app.example.com/dashboard?id=1")
    assert not scope.is_in_scope("https://app.example.com/other")
    assert not scope.is_in_scope("https://admin.example.com/dashboard")
    assert not scope.is_in_scope("https://evil.com/")


def test_asset_discovery_drops_hosts_outside_scope(monkeypatch):
    scope = Scope(
        allowed_domains=["example.com", "*.example.com"],
        excluded_domains=["admin.example.com"],
    )
    discovery = AssetDiscovery(scope=scope)

    monkeypatch.setattr(asset_discovery_module, "COMMON_SUBDOMAINS", ["www", "admin"])

    async def fake_resolve(hostname):
        return {
            "example.com": "1.1.1.1",
            "www.example.com": "1.1.1.2",
            "admin.example.com": "1.1.1.3",
        }.get(hostname)

    scanned_hosts = []

    async def fake_scan_ports(host, on_event=None):
        scanned_hosts.append(host)
        return [DiscoveredPort(host=host, port=443, service="https")]

    async def fake_detect(ports, on_event=None):
        return []

    monkeypatch.setattr(discovery, "_resolve_host", fake_resolve)
    monkeypatch.setattr(discovery, "_scan_ports", fake_scan_ports)
    monkeypatch.setattr(discovery, "_detect_technologies", fake_detect)

    result = asyncio.run(discovery.discover("https://example.com"))

    assert {item.hostname for item in result.subdomains} == {"example.com", "www.example.com"}
    assert scanned_hosts == ["example.com", "www.example.com"]


@dataclass
class DummyResponsibilityReport:
    def summary(self):
        return "responsibility-summary"


class DummyAI:
    def close(self):
        pass


class DummyMind:
    def close(self):
        pass

    def enhance_prompt(self, _query):
        return ""


class DummyConsequenceAnalyzer:
    pass


class DummyResponsibility:
    def __init__(self, hunter_mind=None):
        self.hunter_mind = hunter_mind

    def start_scan(self, _scan_id):
        pass

    def pre_scan_check(self, _target_url, _in_scope, _instructions):
        return []

    def close_learning_loop(self, _state, _consequence_reports):
        return DummyResponsibilityReport()

    def on_module_complete(self, *_args, **_kwargs):
        pass

    def should_stop_scanning(self):
        return False, ""


class DummyPayloadEngine:
    def close(self):
        pass


class DummyRLPolicyAgent:
    def __init__(self, *args, **kwargs):
        self.exploration_strategy_name = "test"

    def start_episode(self, episode_id=None):
        self.episode_id = episode_id

    def end_episode(self):
        return {"steps": 0, "total_reward": 0.0, "mean_reward": 0.0}

    def summary(self, _top_n=3):
        return "rl-summary"

    def rank_modules(self, modules, **_kwargs):
        return list(modules)

    def choose_action(self, available_modules, **_kwargs):
        return available_modules[0]

    def observe(self, *_args, **_kwargs):
        return 0.0

    @property
    def reward_interpreter(self):
        class DummyTeachingMemory:
            def record_teaching(self, *_args, **_kwargs):
                pass

            def check_taught_hits(self, *_args, **_kwargs):
                return 0

        class DummyInterpreter:
            def __init__(self):
                self._last_breakdown = {}
                self.teaching_memory = DummyTeachingMemory()

        return DummyInterpreter()


class DummyScanner:
    def __init__(self, _client):
        self.client = _client

    async def setup(self):
        pass

    async def run(self, _state):
        return []

    async def teardown(self):
        pass


def _make_orchestrator(monkeypatch, tmp_path, modules=None, checkpoint_name="scan-checkpoint.json"):
    monkeypatch.setattr(orchestrator_module, "AIBrain", DummyAI)
    monkeypatch.setattr(orchestrator_module, "HunterMind", DummyMind)
    monkeypatch.setattr(orchestrator_module, "ConsequenceAnalyzer", DummyConsequenceAnalyzer)
    monkeypatch.setattr(orchestrator_module, "ResponsibilityEngine", DummyResponsibility)
    monkeypatch.setattr(orchestrator_module, "AdaptivePayloadEngine", DummyPayloadEngine)
    monkeypatch.setattr(orchestrator_module, "RLPolicyAgent", DummyRLPolicyAgent)
    monkeypatch.setattr(
        orchestrator_module,
        "CHECKPOINT_FILE",
        str(tmp_path / checkpoint_name),
    )
    return orchestrator_module.Orchestrator(
        target=Target(url="https://example.com", scope=Scope(allowed_domains=["example.com"])),
        modules=modules or ["module-a"],
        use_ai=False,
        use_tui=False,
        use_memory=False,
        auto_confirm=True,
    )


def test_orchestrator_preserves_aborted_phase(monkeypatch, tmp_path):
    orchestrator = _make_orchestrator(monkeypatch, tmp_path)

    async def fake_pre_engagement(_state):
        return False

    monkeypatch.setattr(orchestrator, "_phase_pre_engagement", fake_pre_engagement)

    state = asyncio.run(orchestrator.run())

    assert state.phase == "aborted"


def test_orchestrator_keeps_failed_checkpoint(monkeypatch, tmp_path):
    orchestrator = _make_orchestrator(monkeypatch, tmp_path, checkpoint_name="failed-checkpoint.json")

    async def fake_pre_engagement(_state):
        return True

    async def fake_recon(_state):
        raise RuntimeError("boom")

    monkeypatch.setattr(orchestrator, "_phase_pre_engagement", fake_pre_engagement)
    monkeypatch.setattr(orchestrator, "_phase_recon", fake_recon)

    state = asyncio.run(orchestrator.run())

    assert state.phase == "failed"
    assert state.errors == ["boom"]
    assert (tmp_path / "failed-checkpoint.json").exists()


def test_orchestrator_consumes_modules_pending_during_scan(monkeypatch, tmp_path):
    orchestrator = _make_orchestrator(monkeypatch, tmp_path, modules=["module-a"])
    orchestrator.target.discovered_params = {"https://example.com": ["q"]}

    async def fake_pre_engagement(_state):
        return True

    async def fake_recon(state):
        state.target = orchestrator.target

    monkeypatch.setattr(orchestrator, "_phase_pre_engagement", fake_pre_engagement)
    monkeypatch.setattr(orchestrator, "_phase_recon", fake_recon)
    monkeypatch.setattr(orchestrator_module, "load_scanner", lambda _name: DummyScanner)

    state = asyncio.run(orchestrator.run())

    assert state.phase == "complete"
    assert state.modules_pending == []
    assert state.modules_run == ["module-a"]


def test_normalize_settings_payload_accepts_camel_case():
    normalized = api_server.normalize_settings_payload(
        {
            "timeout": 45,
            "userAgent": "AgentHunter/Test",
            "rateLimit": 7,
            "proxy": "http://127.0.0.1:8080",
            "outputDir": "./custom",
            "autoReport": False,
            "verifySsl": False,
            "followRedirects": False,
            "saveLogs": False,
        }
    )

    assert normalized == {
        "timeout": 45,
        "user_agent": "AgentHunter/Test",
        "rate_limit": 7,
        "proxy": "http://127.0.0.1:8080",
        "output_dir": "./custom",
        "auto_report": False,
        "verify_ssl": False,
        "follow_redirects": False,
        "save_logs": False,
    }
