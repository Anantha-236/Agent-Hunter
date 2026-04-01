#!/usr/bin/env python3
"""
Bug Bounty Agent — Entry Point
Usage:
    python main.py --target https://example.com --scope "*.example.com"
    python main.py --target https://example.com --modules sql_injection xss_scanner ssrf
    python main.py --help
"""
import argparse
import asyncio
import logging
import os
import sys

from config.settings import LOG_LEVEL, OUTPUT_DIR, OLLAMA_MODEL, ENABLED_MODULES, HUNTER_POLICY_BACKEND
from core.models import Scope, Target
from core.orchestrator import Orchestrator, CHECKPOINT_FILE
from core.bbp_policy import BBPPolicy
from core.pre_engagement import PreEngagementChecklist
from core.rl_agent import RLPolicyAgent
from interaction.base import InteractionMode
from interaction.manager import InteractionManager
from reporting.reporter import Reporter


def load_local_env() -> None:
    """Load simple KEY=VALUE pairs from local env files without extra deps."""
    for path in (".env.local", ".env"):
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    os.environ.setdefault(key.strip(), value.strip().strip("\"'"))
        except Exception:
            continue


def setup_logging(level: str = LOG_LEVEL) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("agent.log"),
        ],
    )


def print_rl_diagnostics(policy: RLPolicyAgent, top_n: int = 10) -> None:
    """Print RL policy diagnostics to terminal (v2 — supports full RL agent)."""
    diag = policy.diagnostics()

    # ── Header ─────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("  Hunter RL Agent — Diagnostics (v2)")
    print("=" * 72)
    print(f"  State file        : {policy.state_file}")
    print(f"  Exploration       : {diag['exploration_strategy']}")
    print(f"  Epsilon           : {diag.get('epsilon', 'N/A')}")
    print(f"  Learning rate     : alpha={diag['alpha']:.4f}")
    print(f"  Discount factor   : gamma={diag.get('gamma', 0.95):.2f}")
    print(f"  Episodes          : {diag['total_episodes']}")
    print(f"  Learning updates  : {diag['total_learning_updates']}")
    print(f"  Q-function        : {diag['q_function_n_actions']} actions × {diag['q_function_state_dim']}d features")
    print(f"  Value backend     : {diag.get('value_backend', 'linear')}")
    print(f"  Replay buffer     : {diag['replay_buffer_size']}/{diag['replay_buffer_capacity']} experiences")

    # ── Module table ───────────────────────────────────────────
    ranked = sorted(
        policy.module_states.items(),
        key=lambda item: item[1].q_value,
        reverse=True,
    )[:top_n]

    total_pulls = sum(st.pulls for st in policy.module_states.values())
    total_successes = sum(st.successes for st in policy.module_states.values())
    total_failures = sum(st.failures for st in policy.module_states.values())

    print(f"\n  Total actions: pulls={total_pulls}, successes={total_successes}, failures={total_failures}")

    if not ranked:
        print("\n  No RL data yet. Run a scan to generate policy experience.")
        print()
        return

    print(f"\n  Top {len(ranked)} Modules (by bandit Q-value):")
    print(f"  {'Module':24} {'Q-val':>8} {'Pulls':>6} {'AvgRew':>8} {'S/F':>8} {'TS(a/b)':>12}")
    print("  " + "-" * 70)

    for name, st in ranked:
        avg_reward = (st.total_reward / st.pulls) if st.pulls else 0.0
        ts_str = f"{st.alpha_ts:.1f}/{st.beta_ts:.1f}" if hasattr(st, 'alpha_ts') else "-"
        print(
            f"  {name:24} {st.q_value:>8.3f} {st.pulls:>6d} "
            f"{avg_reward:>8.3f} {f'{st.successes}/{st.failures}':>8} {ts_str:>12}"
        )

    # ── Q-function value estimates ─────────────────────────────
    if (
        hasattr(policy, 'q_function')
        and policy.q_function
        and getattr(policy.q_function, "state_dim", 0) > 0
        and hasattr(policy.q_function, "weights")
    ):
        print(f"\n  Q-function weight norms (per action):")
        action_names = policy.action_space.modules if hasattr(policy, 'action_space') else []
        for a_idx, w in enumerate(policy.q_function.weights):
            norm = sum(x*x for x in w) ** 0.5
            bias = policy.q_function.biases[a_idx] if a_idx < len(policy.q_function.biases) else 0.0
            act_name = action_names[a_idx] if a_idx < len(action_names) else f"action_{a_idx}"
            print(f"    {act_name:24} ||w||={norm:.4f}  bias={bias:.4f}")

    # ── Context bias ───────────────────────────────────────────
    if policy.tech_bias:
        print("\n  Context Bias Learned For:")
        for tech, module_biases in sorted(policy.tech_bias.items())[:8]:
            top_mods = sorted(module_biases.items(), key=lambda kv: abs(kv[1]), reverse=True)[:3]
            bias_str = ", ".join(f"{m}={v:+.3f}" for m, v in top_mods)
            print(f"    {tech:20} {bias_str}")

    # ── Thompson Sampling posteriors from module ranking ──────
    module_ranking = diag.get('module_ranking', [])
    has_ts = any(m.get('thompson_alpha', 1.0) != 1.0 or m.get('thompson_beta', 1.0) != 1.0
                 for m in module_ranking)
    if has_ts:
        print(f"\n  Thompson Sampling Posteriors:")
        ranked_ts = sorted(module_ranking,
                           key=lambda m: m['thompson_alpha'] / (m['thompson_alpha'] + m['thompson_beta']),
                           reverse=True)[:top_n]
        for m in ranked_ts:
            a, b = m['thompson_alpha'], m['thompson_beta']
            mean = a / (a + b)
            print(f"    {m['module']:24} mean={mean:.4f}  a={a:.1f}  b={b:.1f}")

    print()
    print("=" * 72)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Autonomous Bug Bounty Agent -- Ollama + RL powered",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target https://example.com
  python main.py --target https://example.com --scope "*.example.com" "api.example.com"
  python main.py --target https://example.com --modules sql_injection xss_scanner ssrf
  python main.py --target https://example.com --proxy http://127.0.0.1:8080
  python main.py --target https://example.com --no-ai --log-level DEBUG
  python main.py --resume
    python main.py --rl-stats
    python main.py --rl-stats --rl-top 15

Interactive modes:
  python main.py --interact text-to-text           # Chat via terminal
  python main.py --interact voice-to-text           # Speak, read response
  python main.py --interact text-to-voice           # Type, hear response
  python main.py --interact voice-to-voice          # Full voice conversation
  python main.py -i voice-to-voice --voice-engine whisper --tts-engine edge-tts
        """
    )
    parser.add_argument("--target", "-t", help="Target URL")
    parser.add_argument("--scope", "-s", nargs="+",
                        help="Allowed domains (supports wildcards: *.example.com)")
    parser.add_argument("--exclude", nargs="+", default=[],
                        help="Excluded domains")
    parser.add_argument("--modules", "-m", nargs="+",
                        help="Specific modules to run (default: all)")
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--cookie", nargs="+", default=[],
                        help="Cookies as key=value pairs")
    parser.add_argument("--header", nargs="+", default=[],
                        help="Custom headers as Key:Value")
    parser.add_argument("--output-dir", default=OUTPUT_DIR,
                        help=f"Output directory (default: {OUTPUT_DIR})")
    parser.add_argument("--no-ai", action="store_true",
                        help="Skip AI-powered strategy and validation (rule engine only)")
    parser.add_argument("--no-tui", action="store_true",
                        help="Disable rich TUI dashboard")
    parser.add_argument("--no-memory", action="store_true",
                        help="Disable persistent scan memory")
    parser.add_argument("--resume", action="store_true",
                        help="Resume an interrupted scan from checkpoint")
    parser.add_argument("--reward-scheme", type=str, default=None,
                        help="Path to custom reward scheme JSON file")
    parser.add_argument("--ollama-model", default=OLLAMA_MODEL,
                        help=f"Ollama model to use (default: {OLLAMA_MODEL})")
    parser.add_argument("--profile", help="Load saved scope profile by name")
    parser.add_argument("--save-profile", help="Save current config as named profile")
    parser.add_argument("--login-url", help="Login URL for authenticated scanning")
    parser.add_argument("--login-user", help="Username for form login")
    parser.add_argument("--login-pass", help="Password for form login")
    parser.add_argument("--bearer-token", help="Bearer token for API auth")
    parser.add_argument("--policy", help="Path to pre-engagement policy JSON file")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Auto-confirm pre-scan safety prompt (skip interactive check)")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification (NOT recommended)")
    parser.add_argument("--health-check", action="store_true",
                        help="Run health checks (Ollama) and exit")
    parser.add_argument("--rl-stats", action="store_true",
                        help="Show RL policy diagnostics and exit")
    parser.add_argument("--rl-top", type=int, default=10,
                        help="Number of top RL modules to display (default: 10)")
    parser.add_argument("--log-level", default=LOG_LEVEL,
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    # ── Interaction mode ───────────────────────────────────────
    parser.add_argument("--interact", "-i",
                        choices=["text-to-text", "voice-to-text",
                                 "text-to-voice", "voice-to-voice"],
                        help="Start interactive chat mode (e.g. --interact voice-to-voice)")
    parser.add_argument("--voice-engine", default="google",
                        choices=["google", "whisper", "sphinx"],
                        help="Speech recognition engine (default: google)")
    parser.add_argument("--tts-engine", default="pyttsx3",
                        choices=["pyttsx3", "edge-tts"],
                        help="Text-to-speech engine (default: pyttsx3)")
    parser.add_argument("--tts-voice", default=None,
                        help="Voice name for TTS (engine-specific)")
    parser.add_argument("--voice-lang", default="en-US",
                        help="Voice recognition language (default: en-US)")
    parser.add_argument("--telegram-bot", action="store_true",
                        help="Run Hunter as a Telegram bot using TELEGRAM_BOT_TOKEN")
    parser.add_argument("--telegram-poll-interval", type=float, default=1.0,
                        help="Telegram polling backoff in seconds when idle")
    return parser.parse_args()


async def main():
    load_local_env()
    args = parse_args()
    setup_logging(args.log_level)
    logger = logging.getLogger("agent")

    # ── Handle health check ──────────────────────────────────
    if args.health_check:
        from utils.health_check import run_health_checks
        results = await run_health_checks()
        failed = sum(1 for r in results if r["status"] == "fail")
        return 1 if failed else 0

    # ── Handle RL diagnostics ────────────────────────────────
    if args.rl_stats:
        modules = args.modules or list(ENABLED_MODULES)
        policy = RLPolicyAgent(
            modules=modules,
            state_file=os.path.join(args.output_dir, "rl_policy_state.json"),
            exploration_strategy="hybrid",
            value_backend=HUNTER_POLICY_BACKEND,
        )
        print_rl_diagnostics(policy, top_n=max(1, args.rl_top))
        return 0

    # ── Handle interactive mode ──────────────────────────────
    if args.telegram_bot:
        from integrations.telegram.bot import TelegramBotService

        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        if not token:
            logger.error("TELEGRAM_BOT_TOKEN is required for --telegram-bot")
            return 1

        service = TelegramBotService(
            token=token,
            poll_interval=max(0.2, args.telegram_poll_interval),
        )
        await service.start()
        return 0

    if args.interact:
        mode = InteractionMode.from_string(args.interact)
        manager = InteractionManager(
            mode=mode,
            voice_engine=args.voice_engine,
            voice_language=args.voice_lang,
            tts_engine=args.tts_engine,
            tts_voice=args.tts_voice,
        )
        async with manager:
            await manager.run()
        return 0

    # ── Handle resume ─────────────────────────────────────────
    resume_path = None
    if args.resume:
        if os.path.exists(CHECKPOINT_FILE):
            resume_path = CHECKPOINT_FILE
            logger.info(f"Resuming from checkpoint: {CHECKPOINT_FILE}")
            import json
            with open(CHECKPOINT_FILE) as f:
                ckpt = json.load(f)
            if not args.target:
                args.target = ckpt.get("target_url", "")
        else:
            logger.error("No checkpoint file found. Start a new scan instead.")
            return 1

    # ── Load profile ───────────────────────────────────────────
    # NOTE: Profile loading must happen BEFORE target validation
    # because a profile can supply the target URL.
    if args.profile:
        from config.profiles import ScopeProfile
        profile = ScopeProfile.load(args.profile)
        if profile:
            logger.info(f"Loaded profile: {args.profile}")
            # Profile values are defaults — CLI args override them
            if not args.target:
                args.target = profile.target_url
            if not args.scope:
                args.scope = profile.scope_domains or None
            if not args.exclude:
                args.exclude = profile.excluded_domains
            if not args.modules:
                args.modules = profile.modules or None
            if not args.proxy:
                args.proxy = profile.proxy or None
            # Merge cookies/headers (CLI wins on conflict)
            profile_cookies = dict(profile.cookies)
            profile_headers = dict(profile.headers)
            # Will be merged below after parsing args.cookie/args.header
            args._profile_cookies = profile_cookies
            args._profile_headers = profile_headers
            # Load policy from profile if not explicitly set via --policy
            if not args.policy and (profile.policy_path or profile.policy_data):
                args._profile_policy_data = profile.get_policy_data()
            else:
                args._profile_policy_data = None
        else:
            logger.warning(f"Profile '{args.profile}' not found — ignoring")
            args._profile_cookies = {}
            args._profile_headers = {}
            args._profile_policy_data = None
    else:
        args._profile_cookies = {}
        args._profile_headers = {}
        args._profile_policy_data = None

    # ── Validate target (after profile loading) ────────────────
    if not args.target:
        logger.error("--target is required (or --resume/--profile with existing target)")
        return 1

    # ── Parse cookies ──────────────────────────────────────────
    cookies = dict(args._profile_cookies)  # Profile defaults
    for c in args.cookie:
        if "=" in c:
            k, v = c.split("=", 1)
            cookies[k.strip()] = v.strip()  # CLI overrides

    # ── Parse headers ──────────────────────────────────────────
    headers = dict(args._profile_headers)  # Profile defaults
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()  # CLI overrides

    # ── Build scope ────────────────────────────────────────────
    from urllib.parse import urlparse
    target_host = urlparse(args.target).hostname
    scope_domains = args.scope or [target_host, f"*.{target_host}"]
    scope = Scope(
        allowed_domains=scope_domains,
        excluded_domains=args.exclude,
    )

    # ── Build target ───────────────────────────────────────────
    target = Target(url=args.target, scope=scope)

    # ── Load reward scheme ─────────────────────────────────────
    reward_scheme = None
    if args.reward_scheme:
        import json
        with open(args.reward_scheme) as f:
            reward_scheme = json.load(f)

    # ── Load pre-engagement policy ─────────────────────────────
    policy = None
    pre_engagement_checklist = None

    # Determine policy source: --policy flag > profile policy
    policy_data = None
    if args.policy:
        import json
        logger.info(f"Loading pre-engagement policy from: {args.policy}")
        with open(args.policy) as f:
            policy_data = json.load(f)
    elif args._profile_policy_data:
        policy_data = args._profile_policy_data
        logger.info("Loading pre-engagement policy from profile")

    if policy_data:
        # Auto-detect format: BBPPolicy or PreEngagementChecklist
        if "pre_engagement_checklist" in policy_data:
            pre_engagement_checklist = PreEngagementChecklist.from_dict(
                policy_data["pre_engagement_checklist"]
            )
            logger.info("Loaded PreEngagementChecklist from policy file")
        else:
            policy = BBPPolicy.from_dict(policy_data)
            logger.info(f"Loaded BBPPolicy for program: {policy.program_name}")

    # ── Override Ollama model if specified ──────────────────────
    if args.ollama_model != OLLAMA_MODEL:
        import config.settings as cfg
        cfg.OLLAMA_MODEL = args.ollama_model

    # ── Print banner ───────────────────────────────────────────
    try:
        from utils.console import print_banner
        print_banner(args.target, scope_domains, len(args.modules or []),
                     not args.no_ai, args.output_dir)
    except Exception:
        print(f"\n🔍 Bug Bounty Agent — Target: {args.target}\n")

    # ── Run scan ───────────────────────────────────────────────
    async with Orchestrator(
        target=target,
        modules=args.modules,
        use_ai=not args.no_ai,
        proxy=args.proxy,
        cookies=cookies,
        headers=headers,
        use_tui=not args.no_tui,
        use_memory=not args.no_memory,
        reward_scheme=reward_scheme,
        policy=policy,
        pre_engagement_checklist=pre_engagement_checklist,
        auto_confirm=args.yes,
        verify_ssl=not args.insecure,
    ) as orch:
        state = await orch.run(resume_from=resume_path)

        # ── Results ────────────────────────────────────────────
        stats = state.stats()

        # Generate summary
        print("\n🧠 Generating scan summary...")
        executive_summary = await orch.generate_report(state)

        # Save reports
        reporter = Reporter(args.output_dir)
        md_path, json_path = reporter.save(state, executive_summary)

        # NOTE: HackerOne integration removed — Hunter operates independently

        # Save profile if requested
        if args.save_profile:
            from config.profiles import ScopeProfile
            profile = ScopeProfile(args.save_profile)
            profile.target_url = args.target
            profile.scope_domains = scope_domains
            profile.cookies = cookies
            profile.headers = headers
            profile.modules = args.modules or []
            profile.excluded_domains = args.exclude or []
            profile.proxy = args.proxy or ""
            profile.platform = ""
            # Save policy reference
            if args.policy:
                profile.policy_path = args.policy
            if policy_data:
                profile.policy_data = policy_data
            profile.save()
            print(f"   Profile   : {args.save_profile} saved")

        # Print results
        try:
            from utils.console import print_results
            print_results(stats, confirmed, orch.reward.total_score)
        except Exception:
            print(f"\nScan Complete!")
            print(f"   Total findings : {stats['total_findings']}")
            print(f"   Confirmed      : {stats['confirmed']}")
            print(f"   Reward Score   : {orch.reward.total_score:+.1f}")

        print(f"\nReports saved:")
        print(f"   Markdown : {md_path}")
        print(f"   JSON     : {json_path}")

        return 0 if not confirmed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
