"""
HackerOne Integration — Main Entrypoint
Connects your completed scan results to HackerOne report submission.

Usage:
    python -m integrations.hackerone.run \
        --target https://example.com \
        --program example \
        --scope "*.example.com" \
        [--dry-run]
"""
import argparse
import asyncio
import logging
import os
import sys

from integrations.hackerone.client import HackerOneClient
from integrations.hackerone.submitter import H1Submitter


def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def parse_args():
    p = argparse.ArgumentParser(description="Run agent scan + submit to HackerOne")
    p.add_argument("--target",   "-t",  required=True,       help="Target URL")
    p.add_argument("--program",  "-p",  required=True,       help="HackerOne program handle")
    p.add_argument("--scope",    "-s",  nargs="+",           help="Allowed domains")
    p.add_argument("--modules",  "-m",  nargs="+",           help="Scanner modules to run")
    p.add_argument("--dry-run",         action="store_true", help="Build reports but do NOT submit to H1")
    p.add_argument("--min-severity",    default="medium",
                   choices=["low", "medium", "high", "critical"],
                   help="Minimum severity to submit (default: medium)")
    p.add_argument("--no-ai",           action="store_true", help="Disable AI validation")
    return p.parse_args()


async def main():
    setup_logging()
    args = parse_args()
    logger = logging.getLogger("h1.run")

    # ── 1. Validate H1 credentials ────────────────────────────────────────────
    h1_id    = os.getenv("H1_API_IDENTIFIER")
    h1_token = os.getenv("H1_API_TOKEN")
    if not h1_id or not h1_token:
        print("\n  Missing HackerOne credentials!")
        print("    Set H1_API_IDENTIFIER and H1_API_TOKEN environment variables")
        sys.exit(1)

    with HackerOneClient(api_identifier=h1_id, api_token=h1_token) as h1:
        if not h1.verify_credentials():
            print("  HackerOne credentials are INVALID (401 Unauthorized)")
            print("    Check your API identifier and token in HackerOne settings.")
            sys.exit(1)

        me = h1.get_me()
        handle = me["data"]["attributes"].get("username", "unknown")
        print(f"\n  Authenticated as: @{handle}")

        # ── 2. Fetch + display program scope ──────────────────────────────────
        print(f"\n  Fetching scope for program: {args.program}")
        scopes = h1.get_program_scope(args.program)
        in_scope = [s for s in scopes
                    if s.get("attributes", {}).get("eligible_for_submission", False)]
        print(f"    {len(in_scope)} in-scope assets found:")
        for s in in_scope[:10]:
            attr = s.get("attributes", {})
            print(f"    [{attr.get('asset_type', '?'):10}] {attr.get('asset_identifier', '?')}")
        if len(in_scope) > 10:
            print(f"    ... and {len(in_scope) - 10} more")

        # ── 3. Run the scan ───────────────────────────────────────────────────
        from core.models import Scope, Target
        from core.orchestrator import Orchestrator

        scope_domains = args.scope or []
        if not scope_domains:
            # Auto-derive from in-scope assets
            scope_domains = [
                s["attributes"]["asset_identifier"].lstrip("*.")
                for s in in_scope
                if s["attributes"].get("asset_type") in ("URL", "WILDCARD", "DOMAIN")
            ] or ["*"]

        target = Target(
            url=args.target,
            scope=Scope(allowed_domains=scope_domains),
        )

        print(f"\n  Starting scan: {args.target}")
        print(f"    Scope: {scope_domains[:5]}")

        async with Orchestrator(
            target=target,
            modules=args.modules,
            use_ai=not args.no_ai,
        ) as orch:
            state = await orch.run()

        stats = state.stats()
        print(f"\n  Scan complete:")
        print(f"    Findings     : {stats['total_findings']}")
        print(f"    Confirmed    : {stats['confirmed']}")
        print(f"    By severity  : {stats['by_severity']}")

        # ── 4. Submit to HackerOne ────────────────────────────────────────────
        min_sev_set = {"medium", "high", "critical"}
        if args.min_severity == "low":
            min_sev_set = {"low", "medium", "high", "critical"}
        elif args.min_severity == "high":
            min_sev_set = {"high", "critical"}
        elif args.min_severity == "critical":
            min_sev_set = {"critical"}

        submitter = H1Submitter(
            client=h1,
            team_handle=args.program,
            dry_run=args.dry_run,
            min_severity=min_sev_set,
        )

        action = "Submitting" if not args.dry_run else "Dry-run preview for"
        print(f"\n  {action} findings to HackerOne...")
        results = submitter.submit_findings(state)

        submitted = [r for r in results if r.success]
        skipped   = [r for r in results if r.skipped]
        errors    = [r for r in results if r.error]

        print(f"\n  Submission results:")
        print(f"    Submitted : {len(submitted)}")
        print(f"    Skipped   : {len(skipped)}")
        print(f"    Errors    : {len(errors)}")

        if submitted:
            print(f"\n  Submitted reports:")
            for r in submitted:
                print(f"    {r.report_url}")

        if errors:
            print(f"\n  Errors:")
            for r in errors:
                finding = next((f for f in state.findings if f.id == r.finding_id), None)
                print(f"    {finding.title if finding else r.finding_id}: {r.error}")


if __name__ == "__main__":
    asyncio.run(main())
