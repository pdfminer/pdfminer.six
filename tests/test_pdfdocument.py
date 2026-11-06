import itertools
from io import BytesIO

import pytest

from pdfminer.pdfdocument import (
    PDFDocument,
    PDFNoPageLabels,
    PDFStandardSecurityHandlerV4,
)
from pdfminer.pdfexceptions import PDFObjectNotFound
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfparser import PDFParser
from pdfminer.pdftypes import PDFObjRef, dict_value, int_value
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

    def test_indirect_crypt_filter_dictionaries_use_identity(self):
        # Parse real indirect objects without invoking password authentication.
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R /TestEncryption 3 0 R >>",
            b"<< /Type /Pages /Kids [6 0 R] /Count 1 >>",
            b"<< /V 4 /R 4 /P -4 /O () /U () /CF 4 0 R /StmF /StdCF /StrF /StdCF >>",
            b"<< /StdCF 5 0 R >>",
            b"<< /CFM /None /Length 16 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] >>",
        ]
        pdf = bytearray(b"%PDF-1.7\n")
        offsets = [0]
        for objid, body in enumerate(objects, start=1):
            offsets.append(len(pdf))
            pdf.extend(f"{objid} 0 obj\n".encode() + body + b"\nendobj\n")
        startxref = len(pdf)
        pdf.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
        for offset in offsets[1:]:
            pdf.extend(f"{offset:010d} 00000 n \n".encode())
        pdf.extend(
            f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
            f"startxref\n{startxref}\n%%EOF\n".encode()
        )

        doc = PDFDocument(PDFParser(BytesIO(pdf)))
        params = dict_value(doc.catalog["TestEncryption"])
        assert isinstance(params["CF"], PDFObjRef)
        assert isinstance(dict_value(params["CF"])["StdCF"], PDFObjRef)
        handler = PDFStandardSecurityHandlerV4.__new__(PDFStandardSecurityHandlerV4)
        handler.param = params

        handler.init_params()

        assert handler.stmf == handler.strf == "StdCF"
        assert handler.cfm["StdCF"](0, 0, b"plaintext") == b"plaintext"

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
