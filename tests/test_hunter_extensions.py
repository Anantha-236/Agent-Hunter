import asyncio

from core.Hunter_brain import AIBrain, SYSTEM_PROMPT
from core.hunter_mind import HunterMind
from core.rl_agent import RLPolicyAgent
from core.rl_environment import EnvironmentState
from interaction.chat import ChatSession


AVAILABLE_MODULES = ["moduleA", "moduleB", "moduleC"]


def _make_state(**overrides) -> EnvironmentState:
    defaults = dict(
        target_url="https://example.com",
        technologies=["django"],
        waf_detected=False,
        waf_name="",
        discovered_urls_count=20,
        discovered_params_count=40,
        ssl_present=True,
        modules_run=[],
        modules_remaining=list(AVAILABLE_MODULES),
        findings_count=0,
        confirmed_count=0,
        severity_counts={},
        unique_vuln_types=set(),
        duplicate_count=0,
        cumulative_reward=0.0,
        last_reward=0.0,
        rewards_history=[],
        elapsed_seconds=0.0,
        avg_module_time=0.0,
        module_last_reward={},
        step=0,
    )
    defaults.update(overrides)
    return EnvironmentState(**defaults)


def test_rl_agent_supports_deep_value_backend(tmp_path):
    state_file = tmp_path / "deep_agent_state.json"
    agent = RLPolicyAgent(
        modules=list(AVAILABLE_MODULES),
        state_file=str(state_file),
        exploration_strategy="hybrid",
        value_backend="deep",
    )

    state = _make_state()
    agent.start_episode("deep-backend")
    action = agent.choose_action(list(AVAILABLE_MODULES), state.technologies, env_state=state)
    before = agent.get_q_values(env_state=state)[action]

    next_state = _make_state(
        modules_run=[action],
        modules_remaining=[m for m in AVAILABLE_MODULES if m != action],
        findings_count=1,
        confirmed_count=1,
        cumulative_reward=1.0,
        last_reward=1.0,
        step=1,
    )
    agent.observe(
        action,
        1.0,
        state.technologies,
        env_state=state,
        next_env_state=next_state,
        done=False,
        findings_data=[{"correct": True, "confidence": 0.95}],
    )
    after = agent.get_q_values(env_state=state)[action]

    assert agent.diagnostics()["value_backend"] == "deep"
    assert after != before

    reloaded = RLPolicyAgent(
        modules=list(AVAILABLE_MODULES),
        state_file=str(state_file),
        exploration_strategy="hybrid",
        value_backend="deep",
    )
    assert reloaded.diagnostics()["value_backend"] == "deep"


class DummyAI:
    _ollama_available = False

    async def _check_ollama(self):
        return False


class FakeResearchTool:
    async def research(self, query: str) -> str:
        return f"Web research for {query}\nSource: https://example.com/research"


def test_chat_session_supports_web_research_command():
    chat = ChatSession(ai_brain=DummyAI(), research_tool=FakeResearchTool())

    response = asyncio.run(chat.process("/search deep neural agents"))

    assert "Web research for deep neural agents" in response
    assert "https://example.com/research" in response


def test_system_prompt_uses_upgraded_cognitive_protocol():
    assert "## Identity" in SYSTEM_PROMPT
    assert "## Reasoning Protocol" in SYSTEM_PROMPT
    assert "## Security Intelligence Mode" in SYSTEM_PROMPT
    assert "Do not confabulate" in SYSTEM_PROMPT


class FlakyAvailabilityOllama:
    def __init__(self):
        self.calls = 0

    async def is_available(self, force: bool = False):
        self.calls += 1
        return self.calls >= 2


def test_ai_brain_rechecks_ollama_after_refresh_interval():
    brain = AIBrain()
    brain.ollama = FlakyAvailabilityOllama()
    brain._ollama_recheck_interval_sec = 0.0

    first = asyncio.run(brain._check_ollama())
    second = asyncio.run(brain._check_ollama())

    assert first is False
    assert second is True


class RecordingOllama:
    def __init__(self, reply: str = "ack"):
        self.reply = reply
        self.prompt = None
        self.system = None

    async def chat(self, prompt: str, system: str, use_chat_endpoint: bool = False):
        self.prompt = prompt
        self.system = system
        return self.reply


class RecordingAI:
    def __init__(self, reply: str = "ack"):
        self._ollama_available = True
        self.ollama = RecordingOllama(reply=reply)

    async def _check_ollama(self):
        return True


def test_chat_session_prioritizes_primary_user_message_for_ollama():
    ai = RecordingAI(reply="I understand.")
    chat = ChatSession(
        ai_brain=ai,
        mind=HunterMind(db_path=":memory:"),
        personal_chat=True,
        channel_name="telegram",
    )

    response = asyncio.run(chat.process("Hi Hunter, I'm Anantha. I'm your developer."))

    assert response == "I understand."
    assert ai.ollama.prompt.startswith("[PRIMARY USER MESSAGE]\nHi Hunter, I'm Anantha. I'm your developer.")
    assert "[MESSAGE PROFILE]" in ai.ollama.prompt
    assert "[EXTENDED REASONING CONTEXT]" not in ai.ollama.prompt


def test_chat_session_marks_ambiguous_requests_for_clarification():
    ai = RecordingAI(reply="What do you need help with specifically?")
    chat = ChatSession(
        ai_brain=ai,
        mind=HunterMind(db_path=":memory:"),
        personal_chat=True,
    )

    asyncio.run(chat.process("help me"))

    assert "needs_clarification: yes" in ai.ollama.prompt
    assert "Ask one direct clarifying question before solving" in ai.ollama.prompt


def test_personal_chat_understands_owner_intro_and_learns_it():
    mind = HunterMind(db_path=":memory:")
    chat = ChatSession(
        ai_brain=DummyAI(),
        mind=mind,
        personal_chat=True,
    )

    response = asyncio.run(chat.process("Hi Hunter, I'm Anantha. I'm your developer."))
    learnings = mind.mistake_memory.get_relevant_learnings("relationship", "owner")

    assert "Anantha" in response
    assert "developer" in response.lower()
    assert "[Domain:" not in response
    assert any("Anantha" in item["insight"] for item in learnings)
    assert any("developer" in item["insight"].lower() for item in learnings)


class FakeTelegramClient:
    def __init__(self):
        self.sent = []

    async def send_message(self, chat_id: int, text: str) -> None:
        self.sent.append((chat_id, text))


class FakeTelegramChat:
    async def process(self, text: str) -> str:
        return f"Hunter heard: {text}"


def test_telegram_bridge_routes_message_to_hunter():
    from integrations.telegram.bot import TelegramBotService

    client = FakeTelegramClient()
    service = TelegramBotService(
        token="test-token",
        client=client,
        chat_factory=lambda: FakeTelegramChat(),
    )

    asyncio.run(service.handle_update({
        "update_id": 1,
        "message": {
            "message_id": 7,
            "chat": {"id": 12345},
            "text": "hello hunter",
        },
    }))

    assert client.sent == [(12345, "Hunter heard: hello hunter")]


def test_telegram_service_uses_personal_chat_sessions_by_default():
    from integrations.telegram.bot import TelegramBotService

    service = TelegramBotService(
        token="test-token",
        client=FakeTelegramClient(),
    )

    session = service._session_for(12345)

    assert isinstance(session, ChatSession)
    assert session.personal_chat is True


class FlakyTelegramPollingClient(FakeTelegramClient):
    def __init__(self):
        super().__init__()
        self.poll_calls = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    async def get_me(self):
        return {"username": "test_bot"}

    async def delete_webhook(self):
        return {}

    async def get_updates(self, offset=None, timeout=20):
        self.poll_calls += 1
        if self.poll_calls == 1:
            raise RuntimeError("temporary telegram conflict")
        if self.poll_calls == 2:
            return [{
                "update_id": 2,
                "message": {
                    "message_id": 8,
                    "chat": {"id": 777},
                    "text": "still there?",
                },
            }]
        await asyncio.sleep(3600)


def test_telegram_bot_recovers_from_polling_errors():
    from integrations.telegram.bot import TelegramBotService

    client = FlakyTelegramPollingClient()
    service = TelegramBotService(
        token="test-token",
        client=client,
        chat_factory=lambda: FakeTelegramChat(),
        poll_interval=0.01,
    )

    async def exercise():
        task = asyncio.create_task(service.start())
        await asyncio.sleep(0.5)
        if not task.done():
            task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        return task

    task = asyncio.run(exercise())
    if task.done() and not task.cancelled() and task.exception():
        raise task.exception()

    assert client.sent == [(777, "Hunter heard: still there?")]
