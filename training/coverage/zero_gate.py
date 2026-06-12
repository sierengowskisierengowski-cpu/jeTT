#!/usr/bin/env python3
"""Block (or warn on) training when MITRE coverage gaps exist."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore


def load_matrix(path: Path) -> tuple[list[dict], list[dict], int]:
    if yaml is None:
        raise SystemExit("pip install pyyaml for coverage/zero_gate.py")
    raw = yaml.safe_load(path.read_text())
    default_min = int(raw.get("defaults", {}).get("min_count", 3))
    required = list(raw.get("required") or [])
    stretch = list(raw.get("stretch") or [])
    return required, stretch, default_min


def main() -> int:
    ap = argparse.ArgumentParser(description="jeTT MITRE coverage gate")
    ap.add_argument("--coverage", default="data/mitre_coverage.json")
    ap.add_argument("--matrix", default="training/coverage/matrix.yaml")
    ap.add_argument("--min", type=int, default=None, help="override matrix min_count")
    ap.add_argument("--warn-only", action="store_true", help="print gaps but exit 0")
    args = ap.parse_args()

    cov_path = Path(args.coverage)
    if not cov_path.exists():
        print(f"[!] missing {cov_path} — run stratified_merge.py first")
        return 1

    coverage: dict[str, int] = json.loads(cov_path.read_text())
    required, stretch, default_min = load_matrix(Path(args.matrix))
    floor = args.min if args.min is not None else default_min

    failed = []
    for entry in required:
        tid = entry["id"]
        have = coverage.get(tid, 0)
        if have < floor:
            failed.append((tid, have, floor, entry.get("note", "")))

    warned = []
    for entry in stretch:
        tid = entry["id"] if isinstance(entry, dict) else entry
        have = coverage.get(tid, 0)
        if have < 1:
            warned.append(tid)

    print(f"=== coverage gate ({cov_path}) ===")
    print(f"  techniques in training set: {len(coverage)}")
    print(f"  required floor: {floor}")
    if failed:
        print("\n  FAIL — required gaps:")
        for tid, have, need, note in failed:
            extra = f"  ({note})" if note else ""
            print(f"    {tid}: have {have}, need {need}{extra}")
    else:
        print("  required: PASS")

    if warned:
        print("\n  stretch (warn): zero coverage:")
        for tid in warned:
            print(f"    {tid}")

    if failed and not args.warn_only:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
