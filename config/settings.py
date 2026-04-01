"""Global configuration for the Bug Bounty Agent.

Loads settings from config/ai_hunter_config.json with env-var overrides.
"""
import json
import os
from typing import Any, Dict, List, Optional

# ── Load master config ────────────────────────────────────────
_CONFIG_PATH = os.path.join(os.path.dirname(__file__), "ai_hunter_config.json")
_CONFIG: Dict[str, Any] = {}
try:
    with open(_CONFIG_PATH, "r", encoding="utf-8") as _f:
        _CONFIG = json.load(_f).get("ai_hunter_config", {})
except FileNotFoundError:
    pass  # Fall back to env vars / defaults

def _cfg(*keys, default=None):
    """Walk into nested config dict."""
    node = _CONFIG
    for k in keys:
        if isinstance(node, dict):
            node = node.get(k)
        else:
            return default
        if node is None:
            return default
    return node


# ── Ollama (local LLM) ───────────────────────────────────────
OLLAMA_URL: str = os.getenv(
    "OLLAMA_URL",
    _cfg("ollama", "base_url", default="http://localhost:11434"),
)
OLLAMA_MODEL: str = os.getenv(
    "OLLAMA_MODEL",
    _cfg("ollama", "models", "primary", default="llama3:8b"),
)
OLLAMA_FALLBACK_MODEL: str = os.getenv(
    "OLLAMA_FALLBACK_MODEL",
    _cfg("ollama", "models", "fallback", default="mistral:7b"),
)
OLLAMA_EMBEDDING_MODEL: str = os.getenv(
    "OLLAMA_EMBEDDING_MODEL",
    _cfg("ollama", "models", "embedding", default="nomic-embed-text"),
)
OLLAMA_TIMEOUT: int = int(os.getenv(
    "OLLAMA_TIMEOUT",
    str(_cfg("ollama", "timeouts", "read_timeout_sec", default=180)),
))
OLLAMA_CONNECT_TIMEOUT: int = int(os.getenv(
    "OLLAMA_CONNECT_TIMEOUT",
    str(_cfg("ollama", "timeouts", "connection_timeout_sec", default=10)),
))
OLLAMA_HEALTH_TIMEOUT: int = int(os.getenv(
    "OLLAMA_HEALTH_TIMEOUT",
    str(_cfg("ollama", "timeouts", "health_check_timeout_sec", default=5)),
))
OLLAMA_RECHECK_INTERVAL_SEC: float = float(os.getenv(
    "OLLAMA_RECHECK_INTERVAL_SEC",
    str(_cfg("ollama", "timeouts", "recheck_interval_sec", default=30)),
))

# Ollama request defaults
OLLAMA_TEMPERATURE: float = float(
    _cfg("ollama", "request_defaults", "options", "temperature", default=0.2)
)
OLLAMA_TOP_P: float = float(
    _cfg("ollama", "request_defaults", "options", "top_p", default=0.9)
)
OLLAMA_TOP_K: int = int(
    _cfg("ollama", "request_defaults", "options", "top_k", default=40)
)
OLLAMA_NUM_CTX: int = int(
    _cfg("ollama", "request_defaults", "options", "num_ctx", default=65536)
)
OLLAMA_NUM_PREDICT: int = int(
    _cfg("ollama", "request_defaults", "options", "num_predict", default=1024)
)
OLLAMA_REPEAT_PENALTY: float = float(
    _cfg("ollama", "request_defaults", "options", "repeat_penalty", default=1.1)
)

# Ollama endpoint paths
OLLAMA_ENDPOINTS: Dict[str, str] = _cfg("ollama", "endpoints", default={
    "health_check": "/",
    "list_models": "/api/tags",
    "generate": "/api/generate",
    "chat": "/api/chat",
    "embeddings": "/api/embeddings",
    "pull_model": "/api/pull",
    "running_models": "/api/ps",
})

# ── HackerOne API — REMOVED (Hunter operates independently) ──
# All H1 settings removed. Hunter generates its own reports.

# ── Error handling config ─────────────────────────────────────
OLLAMA_ERROR_HANDLING: Dict[str, Any] = _cfg("error_handling", "ollama_failures", default={})

# ── HTTP ──────────────────────────────────────────────────────
HTTP_TIMEOUT: int = 15
HTTP_MAX_RETRIES: int = 3
HTTP_CONCURRENCY: int = int(os.getenv("MAX_CONCURRENT_SCANS", "10"))
HTTP_DELAY_BETWEEN_REQUESTS: float = 0.3
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

# ── Scanning ──────────────────────────────────────────────────
MAX_CRAWL_DEPTH: int = 3
MAX_URLS_PER_TARGET: int = 500
SCAN_TIMEOUT_PER_MODULE: int = 300
OUTPUT_DIR: str = os.getenv("OUTPUT_DIR", "./reports")
LOG_LEVEL: str = os.getenv("LOG_LEVEL", os.getenv("AGENT_LOG_LEVEL", "INFO"))

class Severity:
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

SEVERITY_ORDER = {
    Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3,
    Severity.LOW: 2, Severity.INFO: 1,
}

ENABLED_MODULES: List[str] = [
    "sql_injection", "ssti", "crlf_injection", "command_injection", "xxe_scanner",
    "xss_scanner", "ssrf", "graphql_scanner",
    "auth_scanner", "idor_scanner", "csrf_scanner", "race_condition",
    "path_traversal", "misconfig_scanner", "host_header",
    "open_redirect", "subdomain_takeover",
]

# ── Health check sequence ─────────────────────────────────────
HEALTH_CHECK_SEQUENCE: List[Dict] = _cfg("health_check_sequence", default=[])

# ── RL / Reward config ────────────────────────────────────────
RL_REWARD_MAP: Dict[str, int] = _cfg("rl_config", "reward_function", default={})
HUNTER_POLICY_BACKEND: str = os.getenv(
    "HUNTER_POLICY_BACKEND",
    _cfg("rl_config", "value_backend", default="deep"),
)

# ── Convenience: full config access ───────────────────────────
def get_config() -> Dict[str, Any]:
    """Return the full loaded config dict."""
    return dict(_CONFIG)
