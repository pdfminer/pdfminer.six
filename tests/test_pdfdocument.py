import itertools
from io import BytesIO

import pytest

from pdfminer.pdfdocument import PDFDocument, PDFNoPageLabels
from pdfminer.pdfexceptions import PDFObjectNotFound
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfparser import PDFParser
from pdfminer.pdftypes import PDFObjRef, dict_value, int_value
from tests.helpers import absolute_sample_path


class TestPdfDocument:
    @pytest.mark.parametrize(
        "sample, expected_names",
        [
            (
                "simple5.pdf",
                {
                    b"Doc-Start",
                    b"heading",
                    b"page.1",
                    b"section*.1",
                    b"section*.2",
                    b"subheading",
                },
            ),
            (
                "contrib/pagelabels.pdf",
                {
                    b"Doc-Start",
                    b"page.1",
                    b"page.2",
                    b"page.iii",
                    b"page.iv",
                    b"section*.1",
                    b"section.1",
                    b"section.2",
                    b"section.3",
                    b"section.4",
                },
            ),
        ],
    )
    def test_get_destinations_name_tree(self, sample, expected_names):
        with open(absolute_sample_path(sample), "rb") as fp:
            doc = PDFDocument(PDFParser(fp))
            destinations = list(doc.get_destinations())

            assert [name for name, _ in destinations] == sorted(expected_names)
            for name, destination in destinations:
                assert destination.objid == doc.get_dest(name).objid

    def test_get_destinations_mixed_catalog(self):
        pdf = BytesIO(b"""%PDF-1.4
1 0 obj << /Type /Catalog /Dests << /chapter 3 0 R >>
    /Names << /Dests << /Names [(chapter) 3 0 R 2 0 R 3 0 R] >> >> >> endobj
2 0 obj <ff> endobj
3 0 obj [4 0 R /Fit] endobj
4 0 obj << /Type /Page >> endobj
trailer << /Root 1 0 R >>
%%EOF""")
        doc = PDFDocument(PDFParser(pdf))
        destinations = list(doc.get_destinations())
        assert [name for name, _ in destinations] == ["chapter", b"chapter", b"\xff"]
        for _, destination in destinations:
            assert isinstance(destination, PDFObjRef)
            assert destination.objid == 3

    def test_no_destinations(self):
        with open(absolute_sample_path("simple1.pdf"), "rb") as fp:
            assert list(PDFDocument(PDFParser(fp)).get_destinations()) == []

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
