"""Test CMap security fixes for CVE-2025-64512."""

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
