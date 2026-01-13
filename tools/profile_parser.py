#!/usr/bin/env python3
"""cProfile wrapper for profiling pdfminer.psparser operations.

Usage:
    python tools/profile_parser.py samples/simple4.pdf
    python tools/profile_parser.py samples/simple4.pdf --sort cumulative
    python tools/profile_parser.py samples/simple4.pdf --limit 20
"""

import argparse
import cProfile
import pstats
import sys
from pathlib import Path
from io import StringIO

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pdfminer.psparser import PSStackParser


def profile_parse_pdf(pdf_path: Path, max_objects: int = 5000) -> None:
    """Profile parsing a PDF file."""
    with open(pdf_path, "rb") as fp:
        parser = PSStackParser(fp)
        objects = []
        try:
            for _ in range(max_objects):
                _, obj = parser.nextobject()
                objects.append(obj)
        except StopIteration:
            pass
        print(f"Parsed {len(objects)} objects from {pdf_path.name}")


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Profile pdfminer.psparser performance",
    )
    parser.add_argument(
        "pdf_file",
        type=Path,
        help="PDF file to profile",
    )
    parser.add_argument(
        "--sort",
        choices=["cumulative", "time", "calls", "name"],
        default="cumulative",
        help="Sort stat

s by (default: cumulative)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=30,
        help="Number of top functions to show (default: 30)",
    )
    parser.add_argument(
        "--max-objects",
        type=int,
        default=5000,
        help="Maximum objects to parse (default: 5000)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Save profile stats to file",
    )

    args = parser.parse_args()

    if not args.pdf_file.exists():
        print(f"Error: PDF file not found: {args.pdf_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Profiling: {args.pdf_file}")
    print(f"Maximum objects: {args.max_objects}")
    print("-" * 80)

    # Run profiler
    profiler = cProfile.Profile()
    profiler.enable()
    profile_parse_pdf(args.pdf_file, args.max_objects)
    profiler.disable()

    # Generate statistics
    stats = pstats.Stats(profiler)

    # Save to file if requested
    if args.output:
        stats.dump_stats(str(args.output))
        print(f"\nProfile data saved to: {args.output}")

    # Print statistics
    print("\n" + "=" * 80)
    print(f"Top {args.limit} functions by {args.sort} time:")
    print("=" * 80)

    stats.strip_dirs()
    stats.sort_stats(args.sort)
    stats.print_stats(args.limit)

    # Print callers for the most expensive functions
    print("\n" + "=" * 80)
    print("Callers of top 5 functions:")
    print("=" * 80)
    stats.print_callers(5)


if __name__ == "__main__":
    main()
