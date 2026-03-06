#!/usr/bin/env python3
"""
Quick script to verify your HackerOne API credentials.
Run: python test_h1_credentials.py
"""
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from integrations.hackerone.client import HackerOneClient, HackerOneError


def main():
    identifier = os.getenv("H1_API_IDENTIFIER")
    token      = os.getenv("H1_API_TOKEN")

    print("=" * 60)
    print("  HackerOne API Credential Test")
    print("=" * 60)

    if not identifier or not token:
        print("\n  Missing credentials!")
        print("""
  Set these environment variables:

    H1_API_IDENTIFIER=your-token-identifier
    H1_API_TOKEN=your-secret-token

  Get them at: https://hackerone.com/settings/api_token/edit
""")
        return

    print(f"\n  Identifier : {identifier[:8]}{'*' * max(0, len(identifier)-8)}")
    print(f"  Token      : {token[:8]}{'*' * max(0, len(token)-8)}")
    print("\n  Testing connection...")

    try:
        with HackerOneClient(identifier, token) as client:
            me = client.get_me()
            attrs = me["data"]["attributes"]
            print(f"\n  SUCCESS!")
            print(f"   Username : @{attrs.get('username', '?')}")
            print(f"   Name     : {attrs.get('name', '?')}")
            print(f"   Signal   : {attrs.get('signal', '?')}")
            print(f"   Impact   : {attrs.get('impact', '?')}")

            # List a few programs
            print("\n  Fetching accessible programs...")
            programs = []
            for p in client.iter_programs():
                programs.append(p)
                if len(programs) >= 5:
                    break
            print(f"  Found {len(programs)} programs (showing first 5):")
            for p in programs:
                a = p.get("attributes", {})
                bounty = "offers bounty" if a.get("offers_bounties") else "no bounty"
                print(f"   - {a.get('handle', '?')} : {a.get('name', '?')} ({bounty})")

    except HackerOneError as e:
        if e.status == 401:
            print("\n  INVALID CREDENTIALS (401 Unauthorized)")
            print("   Double-check your identifier and token.")
        else:
            print(f"\n  API Error {e.status}: {e.body[:200]}")
    except Exception as e:
        print(f"\n  Connection error: {e}")


if __name__ == "__main__":
    main()
