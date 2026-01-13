#!/usr/bin/env python3
"""Compare two benchmark runs and show performance differences.

Usage:
    python tools/compare_benchmarks.py baseline.json current.json
    python tools/compare_benchmarks.py --threshold 10 baseline.json current.json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def load_benchmark_data(filepath: Path) -> dict[str, Any]:
    """Load benchmark data from JSON file."""
    with open(filepath) as f:
        return json.load(f)


def compare_benchmarks(
    baseline: dict[str, Any],
    current: dict[str, Any],
    threshold: float = 10.0,
) -> None:
    """Compare two benchmark runs and report differences."""
    baseline_benchmarks = {b["name"]: b for b in baseline["benchmarks"]}
    current_benchmarks = {b["name"]: b for b in current["benchmarks"]}

    print("=" * 100)
    print(f"{'Benchmark':<60} {'Baseline':>12} {'Current':>12} {'Change':>10}")
    print("=" * 100)

    regressions = []
    improvements = []
    no_change = []

    for name in sorted(current_benchmarks.keys()):
        if name not in baseline_benchmarks:
            print(f"{name:<60} {'N/A':>12} {'NEW':>12} {'N/A':>10}")
            continue

        baseline_time = baseline_benchmarks[name]["stats"]["mean"]
        current_time = current_benchmarks[name]["stats"]["mean"]

        change_pct = ((current_time - baseline_time) / baseline_time) * 100

        # Format output
        baseline_str = f"{baseline_time * 1000:.3f}ms"
        current_str = f"{current_time * 1000:.3f}ms"

        if abs(change_pct) < threshold:
            change_str = f"{change_pct:+.1f}%"
            no_change.append((name, change_pct))
            print(f"{name:<60} {baseline_str:>12} {current_str:>12} {change_str:>10}")
        elif change_pct < 0:
            change_str = f"✓ {change_pct:+.1f}%"
            improvements.append((name, change_pct))
            print(f"{name:<60} {baseline_str:>12} {current_str:>12} \033[92m{change_str:>10}\033[0m")
        else:
            change_str = f"✗ {change_pct:+.1f}%"
            regressions.append((name, change_pct))
            print(f"{name:<60} {baseline_str:>12} {current_str:>12} \033[91m{change_str:>10}\033[0m")

    print("=" * 100)
    print()

    # Summary
    print("Summary:")
    print(f"  Total benchmarks: {len(current_benchmarks)}")
    print(f"  \033[92mImprovements (faster): {len(improvements)}\033[0m")
    print(f"  \033[91mRegressions (slower): {len(regressions)}\033[0m")
    print(f"  No significant change (<{threshold}%): {len(no_change)}")
    print()

    if improvements:
        print("\033[92mTop Improvements:\033[0m")
        for name, change in sorted(improvements, key=lambda x: x[1])[:5]:
            print(f"  {name}: {change:.1f}%")
        print()

    if regressions:
        print("\033[91mRegressions (need attention):\033[0m")
        for name, change in sorted(regressions, key=lambda x: -x[1]):
            print(f"  {name}: {change:+.1f}%")
        print()

    # Exit with error if regressions exceed threshold
    if regressions:
        max_regression = max(r[1] for r in regressions)
        if max_regression > threshold:
            print(f"\033[91m❌ FAILED: Performance regression detected (>{threshold}%)\033[0m")
            sys.exit(1)

    print("\033[92m✓ PASSED: No significant performance regressions\033[0m")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Compare two benchmark runs",
    )
    parser.add_argument(
        "baseline",
        type=Path,
        help="Baseline benchmark JSON file",
    )
    parser.add_argument(
        "current",
        type=Path,
        help="Current benchmark JSON file",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=10.0,
        help="Regression threshold percentage (default: 10%%)",
    )

    args = parser.parse_args()

    if not args.baseline.exists():
        print(f"Error: Baseline file not found: {args.baseline}", file=sys.stderr)
        sys.exit(1)

    if not args.current.exists():
        print(f"Error: Current file not found: {args.current}", file=sys.stderr)
        sys.exit(1)

    print(f"Comparing benchmarks:")
    print(f"  Baseline: {args.baseline}")
    print(f"  Current:  {args.current}")
    print(f"  Threshold: ±{args.threshold}%")
    print()

    baseline_data = load_benchmark_data(args.baseline)
    current_data = load_benchmark_data(args.current)

    compare_benchmarks(baseline_data, current_data, args.threshold)


if __name__ == "__main__":
    main()
