import itertools
import subprocess
import sys
import textwrap

import pytest

from pdfminer.pdfdocument import PDFDocument, PDFNoPageLabels
from pdfminer.pdfexceptions import PDFObjectNotFound
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfparser import PDFParser
from pdfminer.pdftypes import dict_value, int_value
from tests.helpers import absolute_sample_path


class TestPdfDocument:
    def test_get_zero_objid_raises_pdfobjectnotfound(self):
        with open(absolute_sample_path("simple1.pdf"), "rb") as in_file:
            parser = PDFParser(in_file)
            doc = PDFDocument(parser)
            with pytest.raises(PDFObjectNotFound):
                doc.getobj(0)

    def test_encrypted_no_id(self):
        # Some documents may be encrypted but not have an /ID key in
        # their trailer. Tests
        # https://github.com/pdfminer/pdfminer.six/issues/594
        path = absolute_sample_path("encryption/encrypted_doc_no_id.pdf")
        with open(path, "rb") as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)
            assert doc.info == [{"Producer": b"European Patent Office"}]

    def test_page_labels(self):
        path = absolute_sample_path("contrib/pagelabels.pdf")
        with open(path, "rb") as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)
            total_pages = int_value(dict_value(doc.catalog["Pages"])["Count"])
            assert list(itertools.islice(doc.get_page_labels(), total_pages)) == [
                "iii",
                "iv",
                "1",
                "2",
                "1",
            ]

    def test_no_page_labels(self):
        path = absolute_sample_path("simple1.pdf")
        with open(path, "rb") as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)

            with pytest.raises(PDFNoPageLabels):
                doc.get_page_labels()

    def test_annotations(self):
        path = absolute_sample_path("contrib/issue-1082-annotations.pdf")
        with open(path, "rb") as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)
            for _i, page in enumerate(PDFPage.create_pages(doc)):
                print(page)


# Simulates a Python build without MD5 (e.g. FIPS configurations): the
# ``hashlib.md5`` attribute is missing and ``hashlib.new("md5")`` is refused.
NO_MD5_PRELUDE = textwrap.dedent(
    """
    import hashlib

    del hashlib.md5
    _new = hashlib.new

    def _new_without_md5(name, *args, **kwargs):
        if name.lower() == "md5":
            raise ValueError("unsupported hash type md5")
        return _new(name, *args, **kwargs)

    hashlib.new = _new_without_md5
    """
)


def run_without_md5(code: str) -> "subprocess.CompletedProcess[str]":
    # Use a subprocess so that other tests keep a working hashlib.
    return subprocess.run(
        [sys.executable, "-c", NO_MD5_PRELUDE + textwrap.dedent(code)],
        capture_output=True,
        text=True,
        check=False,
    )


EXTRACT_TEXT = """
from pdfminer.high_level import extract_text
print(len(extract_text({path!r}, password={password!r})))
"""

LEGACY_SAMPLES = [
    "encryption/rc4-40.pdf",
    "encryption/rc4-128.pdf",
    "encryption/aes-128.pdf",
]


class TestWithoutMD5:
    def test_import_without_md5(self):
        result = run_without_md5(
            """
            import pdfminer.pdfdocument
            import pdfminer.high_level
            """
        )
        assert result.returncode == 0, result.stderr

    def test_unencrypted_pdf_without_md5(self):
        path = absolute_sample_path("simple1.pdf")
        result = run_without_md5(EXTRACT_TEXT.format(path=path, password=""))
        assert result.returncode == 0, result.stderr
        assert int(result.stdout) > 0

    @pytest.mark.parametrize("password", ["usersecret", "ownersecret"])
    def test_aes_256_r6_without_md5(self, password):
        path = absolute_sample_path("encryption/aes-256-r6.pdf")
        result = run_without_md5(EXTRACT_TEXT.format(path=path, password=password))
        assert result.returncode == 0, result.stderr
        assert int(result.stdout) > 0

    @pytest.mark.parametrize("sample", LEGACY_SAMPLES)
    def test_legacy_encryption_without_md5_raises(self, sample):
        path = absolute_sample_path(sample)
        result = run_without_md5(EXTRACT_TEXT.format(path=path, password="foo"))
        assert result.returncode != 0
        assert "PDFMD5Unavailable" in result.stderr
        assert "requires MD5" in result.stderr

    @pytest.mark.parametrize("sample", LEGACY_SAMPLES)
    def test_legacy_encryption_with_md5(self, sample):
        with open(absolute_sample_path(sample), "rb") as fp:
            doc = PDFDocument(PDFParser(fp), password="foo")
            assert list(PDFPage.create_pages(doc))
