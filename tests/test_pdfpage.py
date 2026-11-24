from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfparser import PDFParser
from tests.helpers import absolute_sample_path


class TestPdfPage:
    def test_page_labels(self):
        path = absolute_sample_path("contrib/pagelabels.pdf")
        expected_labels = ["iii", "iv", "1", "2", "1"]

        with open(path, "rb") as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)
            for i, page in enumerate(PDFPage.create_pages(doc)):
                assert page.label == expected_labels[i]
                assert page.page_number == i

    def test_page_number_with_get_pages_and_manual_init(self) -> None:
        path = absolute_sample_path("contrib/pagelabels.pdf")

        with open(path, "rb") as fp:
            pages = list(PDFPage.get_pages(fp, pagenos=[1, 3]))
        assert [page.page_number for page in pages] == [1, 3]
        assert all(isinstance(page.pageid, int) for page in pages)

        with open(path, "rb") as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)
            first_page = next(PDFPage.create_pages(doc))
            manual_page = PDFPage(
                doc,
                first_page.pageid,
                first_page.attrs,
                first_page.label,
            )
            assert manual_page.page_number is None
