#!/usr/bin/env python3
"""
Prompt Shield - run comparison.

Diffs two benchmark.py --out files prompt by prompt, so the value of the deep
LLM tier is reported as specific techniques caught and specific false positives
cleared, rather than as a pair of aggregate F1 numbers.

Prompts are joined on the stable "id" hash written by benchmark.py, so the two
runs can be reordered or filtered independently and still line up.

Part of: Prompt Shield
Author: Jace
Version: 0.1.0

Usage:
    python compare_runs.py fast.json deep.json
    python compare_runs.py fast.json deep.json --threshold 20
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Attacker-controlled text is echoed to the terminal here. Terminals are not a
# rendering target that executes markup, but keep it capped and never pass this
# through to a web view without escaping.
_PREVIEW = 62


def load_run(path: Path) -> Dict[str, Any]:
    """Load a --out file, failing loudly if it predates per-prompt provenance."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        sys.exit(f"error: {path} not found. Run benchmark.py --out {path.name} first.")
    except json.JSONDecodeError as exc:
        sys.exit(f"error: {path} is not valid JSON ({exc}).")

    if "per_prompt" not in data:
        sys.exit(
            f"error: {path} has no per_prompt data. It was written by an older\n"
            f"       benchmark.py. Re-run the benchmark to regenerate it."
        )
    return data


def describe(label: str, run: Dict[str, Any]) -> str:
    """One-line summary of how a run was configured."""
    if run.get("adjudicator"):
        band = run.get("band") or ["?", "?"]
        tier = f"deep tier ON (band {band[0]:.0f}-{band[1]:.0f})"
    else:
        tier = "deep tier OFF"
    return f"{label}: {tier}, {run.get('attacks', '?')} attacks / {run.get('benign', '?')} benign"


def align(before: Dict[str, Any], after: Dict[str, Any]) -> Tuple[List[Tuple[dict, dict]], int, int]:
    """Join two runs on prompt id. Returns (pairs, only_in_before, only_in_after)."""
    b = {r["id"]: r for r in before["per_prompt"]}
    a = {r["id"]: r for r in after["per_prompt"]}
    shared = b.keys() & a.keys()
    pairs = sorted(
        ((b[i], a[i]) for i in shared),
        key=lambda pair: (pair[0]["label"], pair[0]["index"]),
    )
    return pairs, len(b.keys() - shared), len(a.keys() - shared)


def classify(row: Dict[str, Any], threshold: float) -> bool:
    """True if this prompt would be blocked at the given threshold."""
    return row["risk_score"] >= threshold


def main() -> None:
    parser = argparse.ArgumentParser(description="Diff two Prompt Shield benchmark runs.")
    parser.add_argument("before", type=Path, help="Baseline results JSON (e.g. fast.json).")
    parser.add_argument("after", type=Path, help="Comparison results JSON (e.g. deep.json).")
    parser.add_argument("--threshold", type=float, default=50.0,
                        help="Threshold at which to report verdict flips (default: 50).")
    args = parser.parse_args()

    before, after = load_run(args.before), load_run(args.after)
    pairs, missing_after, missing_before = align(before, after)

    print("\n=== Prompt Shield run comparison ===")
    print(f"  {describe('before', before)}")
    print(f"  {describe('after ', after)}")
    print(f"  joined on {len(pairs)} prompts at threshold {args.threshold:.0f}")
    if missing_after or missing_before:
        print(f"  WARNING: corpora differ - {missing_after} only in before, "
              f"{missing_before} only in after. Compare runs over the same set.")

    # Score movements, regardless of whether they flip the verdict.
    moved = [(b, a) for b, a in pairs if b["risk_score"] != a["risk_score"]]
    if not moved:
        print("\n  No prompt changed score. The two runs are equivalent.")
    else:
        print(f"\n  Scores changed on {len(moved)} prompt(s):")
        for b, a in moved:
            print(f"    {b['label']:6} {b['risk_score']:5.1f} -> {a['risk_score']:5.1f}  "
                  f"[{a['decided_by']}]  {a['preview'][:_PREVIEW]}")
            if a.get("adjudicator_reason"):
                print(f"           reason: {a['adjudicator_reason']}")

    # Verdict flips at the chosen threshold: the part that moves the metrics.
    gained, lost, cleared, introduced = [], [], [], []
    for b, a in pairs:
        was, now = classify(b, args.threshold), classify(a, args.threshold)
        if was == now:
            continue
        bucket = {
            ("attack", False): gained,      # missed -> caught
            ("attack", True): lost,         # caught -> missed
            ("benign", False): introduced,  # clean  -> false positive
            ("benign", True): cleared,      # false positive -> clean
        }[(b["label"], was)]
        bucket.append(a)

    print(f"\n  Verdict flips at threshold {args.threshold:.0f}:")
    print(f"    attacks newly caught   : {len(gained)}")
    print(f"    attacks newly missed   : {len(lost)}      <-- regressions")
    print(f"    false positives cleared: {len(cleared)}")
    print(f"    false positives added  : {len(introduced)}  <-- regressions")

    for title, rows in (("Newly caught", gained), ("NEWLY MISSED", lost),
                        ("False positives cleared", cleared),
                        ("FALSE POSITIVES ADDED", introduced)):
        if rows:
            print(f"\n  {title}:")
            for r in rows:
                print(f"    [{r['decided_by']}] {r['preview'][:_PREVIEW]}")

    # Which tier carried the load in the 'after' run.
    tiers: Dict[str, int] = {}
    for _, a in pairs:
        tiers[a["decided_by"]] = tiers.get(a["decided_by"], 0) + 1
    breakdown = ", ".join(f"{k} {v}" for k, v in sorted(tiers.items()))
    print(f"\n  Decided by tier (after): {breakdown}")

    if lost or introduced:
        print("\n  Net: the deep tier introduced regressions. Review them before "
              "reporting the aggregate delta.")
    print()


if __name__ == "__main__":
    main()
