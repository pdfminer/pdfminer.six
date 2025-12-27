#!/usr/bin/env python3
"""Convert CMap pickle files to secure JSON format.

This standalone script converts .pickle.gz CMap files to .json.gz format,
eliminating the arbitrary code execution vulnerability from pickle deserialization.

Usage:
    python tools/convert_cmaps_to_json.py <pickle_file.pickle.gz> <output_file.json.gz>

Example:
    python tools/convert_cmaps_to_json.py custom-cmap.pickle.gz custom-cmap.json.gz
"""

import gzip
import json
import pickle
import sys
from pathlib import Path


def convert_pickle_to_json(pickle_path: str, json_path: str) -> None:
    """Convert a pickle.gz CMap file to json.gz format.

    Args:
        pickle_path: Path to the input .pickle.gz file
        json_path: Path to the output .json.gz file

    Raises:
        FileNotFoundError: If pickle_path doesn't exist
        ValueError: If the pickle file contains non-serializable data
    """
    if not Path(pickle_path).exists():
        raise FileNotFoundError(f"Pickle file not found: {pickle_path}")

    # Load pickle data
    with gzip.open(pickle_path, "rb") as gzfile:
        data = pickle.load(gzfile)

    # The pickle data should be a dictionary with CODE2CID, IS_VERTICAL, etc.
    if not isinstance(data, dict):
        raise ValueError(f"Expected dict from pickle, got {type(data)}")

    # Write JSON data
    with gzip.open(json_path, "wt", encoding="utf-8") as gzfile:
        json.dump(data, gzfile, ensure_ascii=False, indent=None, separators=(",", ":"))

    print(f"✓ Converted {pickle_path} -> {json_path}")


def main() -> int:
    """Main entry point for the conversion script."""
    if len(sys.argv) != 3:
        print(__doc__)
        print("\nError: Expected 2 arguments", file=sys.stderr)
        print(
            "Usage: python tools/convert_cmaps_to_json.py <input.pickle.gz> <output.json.gz>",
            file=sys.stderr,
        )
        return 1

    pickle_path = sys.argv[1]
    json_path = sys.argv[2]

    try:
        convert_pickle_to_json(pickle_path, json_path)
        return 0
    except Exception as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
