#!/usr/bin/env python3
"""
validate_results.py
Compares Agent-Hunter's output against the ground-truth findings.yaml
and prints a precision/recall scorecard per category.

Usage:
    python3 validate_results.py --agent-output <path-to-agent-json>

Agent output must be a JSON array of objects with at minimum:
  { "type": "...", "url": "...", "severity": "..." }
"""

import json
import yaml
import argparse
import sys
from collections import defaultdict

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def load_expected(path="expected-findings/findings.yaml"):
    with open(path) as f:
        data = yaml.safe_load(f)
    findings = []
    for target_name, target in data["targets"].items():
        category = target["category"]
        for finding in target.get("expected", []):
            findings.append({
                "target": target_name,
                "category": category,
                "type": finding.get("type", ""),
                "severity": finding.get("severity", "MEDIUM"),
            })
    return findings


def score(expected, detected):
    by_category = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

    detected_types = defaultdict(set)
    for d in detected:
        cat = d.get("category", "unknown").lower()
        detected_types[cat].add(d.get("type", "").lower())

    for e in expected:
        cat = e["category"]
        etype = e["type"].lower()
        if etype in detected_types[cat]:
            by_category[cat]["tp"] += 1
        else:
            by_category[cat]["fn"] += 1

    for d in detected:
        cat = d.get("category", "unknown").lower()
        dtype = d.get("type", "").lower()
        expected_types = {e["type"].lower() for e in expected if e["category"] == cat}
        if dtype not in expected_types:
            by_category[cat]["fp"] += 1

    return by_category


def print_report(scores):
    print("\n" + "═" * 60)
    print("  AGENT-HUNTER VALIDATION SCORECARD")
    print("═" * 60)
    total_tp = total_fp = total_fn = 0

    for cat, s in sorted(scores.items()):
        tp, fp, fn = s["tp"], s["fp"], s["fn"]
        precision = tp / (tp + fp) if (tp + fp) else 0
        recall    = tp / (tp + fn) if (tp + fn) else 0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
        total_tp += tp; total_fp += fp; total_fn += fn

        status = "✅" if f1 >= 0.7 else ("⚠️ " if f1 >= 0.4 else "❌")
        print(f"\n  {status} [{cat.upper()}]")
        print(f"     True Positives  : {tp}")
        print(f"     False Positives : {fp}")
        print(f"     False Negatives : {fn}")
        print(f"     Precision       : {precision:.0%}")
        print(f"     Recall          : {recall:.0%}")
        print(f"     F1 Score        : {f1:.2f}")

    total_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 0
    total_recall    = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 0
    total_f1        = 2 * total_precision * total_recall / (total_precision + total_recall) if (total_precision + total_recall) else 0

    print("\n" + "─" * 60)
    print(f"  OVERALL  —  Precision: {total_precision:.0%}  |  Recall: {total_recall:.0%}  |  F1: {total_f1:.2f}")
    print("═" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent-output", required=True, help="Path to agent's JSON output file")
    parser.add_argument("--expected", default="expected-findings/findings.yaml")
    args = parser.parse_args()

    with open(args.agent_output) as f:
        detected = json.load(f)

    expected = load_expected(args.expected)
    scores   = score(expected, detected)
    print_report(scores)


if __name__ == "__main__":
    main()
