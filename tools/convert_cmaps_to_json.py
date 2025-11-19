#!/usr/bin/env python3
"""Convert all CMap pickle files to secure JSON format.

This script converts all .pickle.gz files in the pdfminer/cmap/ directory
to .json.gz format, eliminating the arbitrary code execution vulnerability
from pickle deserialization.

Usage:
    python tools/convert_cmaps_to_json.py
"""

import sys
from pathlib import Path

# Add parent directory to path to import pdfminer
sys.path.insert(0, str(Path(__file__).parent.parent))

from pdfminer.cmapdb import CMapDB


def main() -> int:
    """Convert all pickle files to JSON format."""
    # Get the cmap directory
    cmap_dir = Path(__file__).parent.parent / "pdfminer" / "cmap"

    if not cmap_dir.exists():
        print(f"Error: CMap directory not found: {cmap_dir}", file=sys.stderr)
        return 1

    # Find all pickle files
    pickle_files = list(cmap_dir.glob("*.pickle.gz"))

    if not pickle_files:
        print(f"No pickle files found in {cmap_dir}", file=sys.stderr)
        return 1

    print(f"Found {len(pickle_files)} pickle files to convert")
    print()

    converted = 0
    errors = 0
    skipped = 0

    for pickle_path in sorted(pickle_files):
        json_path = pickle_path.with_suffix(".json.gz").with_suffix(".json.gz")
        # Replace .pickle.gz with .json.gz
        json_path = Path(str(pickle_path).replace(".pickle.gz", ".json.gz"))

        # Skip if JSON already exists and is newer
        if json_path.exists():
            if json_path.stat().st_mtime >= pickle_path.stat().st_mtime:
                print(f"⏭  Skipping {pickle_path.name} (JSON already exists)")
                skipped += 1
                continue

        try:
            print(f"🔄 Converting {pickle_path.name}...", end=" ")
            CMapDB.convert_pickle_to_json(str(pickle_path), str(json_path))
            print("✓")
            converted += 1
        except Exception as e:
            print(f"✗ Error: {e}")
            errors += 1

    print()
    print("Conversion complete:")
    print(f"  ✓ Converted: {converted}")
    print(f"  ⏭  Skipped: {skipped}")
    print(f"  ✗ Errors: {errors}")

    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
