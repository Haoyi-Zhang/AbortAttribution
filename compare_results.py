#!/usr/bin/env python3
"""Exact scientific-output comparison, intentionally excluding process timings."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

NAMES = ("cases.jsonl", "certificates.jsonl", "mutations.jsonl", "omission-probes.jsonl",
         "case-outcomes.json", "negative-controls.json", "disclosure.json", "timing.json",
         "exponents.json", "compiler-cases.jsonl", "compiler-certificates.jsonl",
         "compiler-mutations.jsonl", "compiler-probes.jsonl", "compiler-regressions.json",
         "compiler-outcomes.json",
         "schnorr-cases.jsonl", "schnorr-mutations.jsonl", "binding-negative-control.json",
         "schnorr-share-substitution.json",
         "schnorr-outcomes.json", "schema-audit.json", "setup-boundary-audit.json",
         "outcomes.json")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expected", type=Path)
    parser.add_argument("observed", type=Path)
    args = parser.parse_args()
    failures = []
    for name in NAMES:
        a, b = args.expected/name, args.observed/name
        if not a.is_file() or not b.is_file():
            failures.append(name + ": missing file")
        elif a.read_bytes() != b.read_bytes():
            failures.append(name + ": different scientific output")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"All {len(NAMES)} deterministic scientific result files agree byte for byte; measurements excluded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
