"""Test CMap security fixes for CVE-2025-64512."""

import gzip
import json
import os
import tempfile
import warnings

from pdfminer.cmapdb import CMapDB


class TestCMapSecurity:
    """Test security fixes for CMap loading."""

    def test_json_format_loading(self):
        """Test that JSON format CMaps load correctly."""
        # Test loading a standard CMap from JSON
        cmap = CMapDB.get_cmap("H")
        assert cmap is not None
        assert str(cmap) == "<CMap: H>"

    def test_unicode_map_json_loading(self):
        """Test that Unicode maps load correctly from JSON."""
        umap = CMapDB.get_unicode_map("Adobe-Japan1", vertical=False)
        assert umap is not None
        assert str(umap) == "<UnicodeMap: Adobe-Japan1>"

        # Verify integer keys are correctly restored
        assert isinstance(umap.cid2unichr, dict)
        # Check a known mapping (CID 1 should map to space)
        assert 1 in umap.cid2unichr
        assert umap.cid2unichr[1] == " "

    def test_pickle_deprecation_warning(self):
        """Test that loading pickle files raises deprecation warning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test pickle CMap
            pickle_path = os.path.join(tmpdir, "TestCMap.pickle.gz")
            test_data = {"IS_VERTICAL": False, "CODE2CID": {65: 1}}

            with gzip.open(pickle_path, "wb") as f:
                import pickle

                pickle.dump(test_data, f)

            # Try to load it via CMAP_PATH
            old_env = os.environ.get("CMAP_PATH")
            try:
                os.environ["CMAP_PATH"] = tmpdir

                # Clear cache to force reload
                CMapDB._cmap_cache.clear()

                # Should raise deprecation warning
                with warnings.catch_warnings(record=True) as w:
                    warnings.simplefilter("always")
                    CMapDB.get_cmap("TestCMap")

                    # Verify deprecation warning was raised
                    assert len(w) == 1
                    assert issubclass(w[0].category, DeprecationWarning)
                    assert "insecure pickle format" in str(w[0].message)

            finally:
                if old_env is not None:
                    os.environ["CMAP_PATH"] = old_env
                elif "CMAP_PATH" in os.environ:
                    del os.environ["CMAP_PATH"]
                CMapDB._cmap_cache.clear()

    def test_json_preferred_over_pickle(self):
        """Test that JSON format is preferred over pickle when both exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create both JSON and pickle versions
            json_path = os.path.join(tmpdir, "TestCMap.json.gz")
            pickle_path = os.path.join(tmpdir, "TestCMap.pickle.gz")

            json_data = {"IS_VERTICAL": True, "CODE2CID": {"65": 1}}
            pickle_data = {"IS_VERTICAL": False, "CODE2CID": {65: 2}}

            with gzip.open(json_path, "wt", encoding="utf-8") as f:
                json.dump(json_data, f)

            with gzip.open(pickle_path, "wb") as f:
                import pickle

                pickle.dump(pickle_data, f)

            # Load via CMAP_PATH
            old_env = os.environ.get("CMAP_PATH")
            try:
                os.environ["CMAP_PATH"] = tmpdir
                CMapDB._cmap_cache.clear()

                # Should load JSON version (IS_VERTICAL=True)
                cmap = CMapDB.get_cmap("TestCMap")
                assert cmap.is_vertical() is True

            finally:
                if old_env is not None:
                    os.environ["CMAP_PATH"] = old_env
                elif "CMAP_PATH" in os.environ:
                    del os.environ["CMAP_PATH"]
                CMapDB._cmap_cache.clear()

    def test_convert_pickle_to_json(self):
        """Test pickle to JSON conversion function."""
        with tempfile.TemporaryDirectory() as tmpdir:
            pickle_path = os.path.join(tmpdir, "test.pickle.gz")
            json_path = os.path.join(tmpdir, "test.json.gz")

            # Create a test pickle file
            test_data = {
                "IS_VERTICAL": False,
                "CODE2CID": {65: 1, 66: 2},
                "CID2UNICHR_H": {1: "A", 2: "B"},
            }

            with gzip.open(pickle_path, "wb") as f:
                import pickle

                pickle.dump(test_data, f)

            # Convert to JSON
            CMapDB.convert_pickle_to_json(pickle_path, json_path)

            # Verify JSON file was created and contains correct data
            assert os.path.exists(json_path)

            with gzip.open(json_path, "rt", encoding="utf-8") as f:
                loaded_data = json.load(f)

            assert loaded_data["IS_VERTICAL"] is False
            assert "65" in loaded_data["CODE2CID"]  # Keys are strings in JSON
            assert loaded_data["CODE2CID"]["65"] == 1

    def test_code2cid_key_conversion(self):
        """Test that CODE2CID nested dictionaries have integer keys."""
        cmap = CMapDB.get_cmap("H")
        assert hasattr(cmap, "code2cid")

        # Verify all keys are integers (not strings)
        def check_keys(d):
            if isinstance(d, dict):
                for k, v in d.items():
                    assert isinstance(k, int), f"Expected int key, got {type(k)}: {k}"
                    check_keys(v)

        check_keys(cmap.code2cid)
