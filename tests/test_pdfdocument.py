import itertools

import pytest

from pdfminer.pdfdocument import (
    PDFDocument,
    PDFNoPageLabels,
    PDFStandardSecurityHandlerV4,
)
from pdfminer.pdfexceptions import PDFObjectNotFound
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfparser import PDFParser
from pdfminer.pdftypes import dict_value, int_value
from pdfminer.psparser import LIT
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

    def test_crypt_filter_without_cfm_uses_identity(self):
        handler = PDFStandardSecurityHandlerV4.__new__(PDFStandardSecurityHandlerV4)
        handler.param = {
            "V": 4,
            "R": 4,
            "P": -4,
            "O": b"",
            "U": b"",
            "CF": {"StdCF": {"Length": 16}},
            "StmF": LIT("StdCF"),
            "StrF": LIT("StdCF"),
        }

        handler.init_params()

        assert handler.cfm["StdCF"](0, 0, b"ciphertext") == b"ciphertext"

    def test_missing_default_crypt_filters_use_identity(self):
        handler = PDFStandardSecurityHandlerV4.__new__(PDFStandardSecurityHandlerV4)
        handler.param = {
            "V": 4,
            "R": 4,
            "P": -4,
            "O": b"",
            "U": b"",
            "CF": {},
        }

        handler.init_params()

        assert handler.stmf == "Identity"
        assert handler.strf == "Identity"
        assert handler.cfm["Identity"](0, 0, b"ciphertext") == b"ciphertext"

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
