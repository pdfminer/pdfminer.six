"""Tests for reproducibility in generating cmap .json.gz files."""

import gzip
import json
import pickle
import time
from pathlib import Path

from tools import conv_cmap
from tools.convert_cmaps_to_json import convert_pickle_to_json


def read_gzip_mtime(filepath: str) -> int | None:
    with gzip.GzipFile(filepath, "rb") as gz:
        # Read a byte to trigger header parsing
        gz.read(1)
        return gz.mtime


class TestConvCmapReproducibility:
    """Test suite for conv_cmap.py gzip reproducibility."""

    def test_conv_cmap_gzip_mtime_is_zero(self, tmp_path: Path) -> None:
        """Verify that conv_cmap.py generates gzip files with mtime=0."""
        # Create a minimal cid2code.txt input file
        input_file = tmp_path / "cid2code.txt"
        input_file.write_text("CID\tH\n0\t00\n1\t01\n")

        # Run conv_cmap main function
        conv_cmap.main(  # type: ignore[no-untyped-call]
            [
                "conv_cmap",
                str(tmp_path),
                "test",
                str(input_file),
            ]
        )

        # Check the generated cmap file
        cmap_file = tmp_path / "H.json.gz"
        assert cmap_file.exists(), "Expected H.json.gz to be generated"
        mtime = read_gzip_mtime(str(cmap_file))
        assert mtime == 0, f"Expected mtime=0 in gzip header, got {mtime}"

        # Check the generated unicode map file
        unicode_file = tmp_path / "to-unicode-test.json.gz"
        assert unicode_file.exists(), "Expected to-unicode-test.json.gz to be generated"
        mtime = read_gzip_mtime(str(unicode_file))
        assert mtime == 0, f"Expected mtime=0 in gzip header, got {mtime}"

    def test_conv_cmap_produces_identical_files(self, tmp_path: Path) -> None:
        """Verify that running conv_cmap twice produces identical output."""
        # Create input file
        input_file = tmp_path / "cid2code.txt"
        input_file.write_text("CID\tH\n0\t41\n1\t42\n2\t43\n")

        # Create two output directories
        outdir1 = tmp_path / "out1"
        outdir2 = tmp_path / "out2"
        outdir1.mkdir()
        outdir2.mkdir()

        # Run conv_cmap twice with same input
        # Sleep 1 second between runs to ensure gzip timestamps would differ
        # if mtime=0 fix is not working (gzip mtime has 1-second resolution)
        conv_cmap.main(  # type: ignore[no-untyped-call]
            [
                "conv_cmap",
                str(outdir1),
                "test",
                str(input_file),
            ]
        )
        time.sleep(1)
        conv_cmap.main(  # type: ignore[no-untyped-call]
            [
                "conv_cmap",
                str(outdir2),
                "test",
                str(input_file),
            ]
        )

        # Compare cmap files
        cmap1 = (outdir1 / "H.json.gz").read_bytes()
        cmap2 = (outdir2 / "H.json.gz").read_bytes()
        assert cmap1 == cmap2, "CMap files should be identical"

        # Compare unicode map files
        unicode1 = (outdir1 / "to-unicode-test.json.gz").read_bytes()
        unicode2 = (outdir2 / "to-unicode-test.json.gz").read_bytes()
        assert unicode1 == unicode2, "Unicode map files should be identical"

    def test_conv_cmap_output_is_valid_json(self, tmp_path: Path) -> None:
        """Verify that conv_cmap output contains valid JSON."""
        input_file = tmp_path / "cid2code.txt"
        input_file.write_text("CID\tH\n0\t41\n1\t42\n")

        conv_cmap.main(  # type: ignore[no-untyped-call]
            [
                "conv_cmap",
                str(tmp_path),
                "test",
                str(input_file),
            ]
        )

        # Verify cmap JSON is valid and readable
        with gzip.open(tmp_path / "H.json.gz", "rt", encoding="utf-8") as f:
            data = json.load(f)
        assert "IS_VERTICAL" in data
        assert "CODE2CID" in data


class TestConvertCmapsToJsonReproducibility:
    """Test suite for convert_cmaps_to_json.py gzip reproducibility."""

    def test_convert_pickle_gzip_mtime_is_zero(self, tmp_path: Path) -> None:
        """Verify that convert_pickle_to_json generates gzip files with mtime=0."""
        # Create a test pickle file
        test_data = {"IS_VERTICAL": False, "CODE2CID": {65: 1, 66: 2}}
        pickle_file = tmp_path / "test.pickle.gz"
        with gzip.open(pickle_file, "wb") as f:
            pickle.dump(test_data, f)

        # Convert pickle to JSON
        json_file = tmp_path / "test.json.gz"
        convert_pickle_to_json(str(pickle_file), str(json_file))

        # Verify mtime is 0
        mtime = read_gzip_mtime(str(json_file))
        assert mtime == 0, f"Expected mtime=0 in gzip header, got {mtime}"

    def test_convert_pickle_produces_identical_files(self, tmp_path: Path) -> None:
        """Verify that converting the same pickle twice produces identical output."""
        # Create test pickle file
        test_data = {
            "IS_VERTICAL": True,
            "CODE2CID": {i: i + 100 for i in range(50)},
        }
        pickle_file = tmp_path / "test.pickle.gz"
        with gzip.open(pickle_file, "wb") as f:
            pickle.dump(test_data, f)

        # Convert twice to the same output path (to ensure embedded filename matches)
        # Sleep 1 second between runs to ensure gzip timestamps would differ
        # if mtime=0 fix is not working (gzip mtime has 1-second resolution)
        json_file = tmp_path / "test.json.gz"
        convert_pickle_to_json(str(pickle_file), str(json_file))
        content1 = json_file.read_bytes()

        time.sleep(1)
        convert_pickle_to_json(str(pickle_file), str(json_file))
        content2 = json_file.read_bytes()

        assert content1 == content2, "Converted files should be identical"

    def test_convert_pickle_output_is_valid_json(self, tmp_path: Path) -> None:
        """Verify that converted output contains valid JSON matching input."""
        test_data = {"key": "value", "nested": {"a": 1, "b": 2}}
        pickle_file = tmp_path / "test.pickle.gz"
        with gzip.open(pickle_file, "wb") as f:
            pickle.dump(test_data, f)

        json_file = tmp_path / "test.json.gz"
        convert_pickle_to_json(str(pickle_file), str(json_file))

        with gzip.open(json_file, "rt", encoding="utf-8") as f:
            loaded_data = json.load(f)
        assert loaded_data == test_data
