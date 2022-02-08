from helpers import absolute_sample_path
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfparser import PDFParser


class TestPdfPage(object):
    def test_page_labels(self):
        path = absolute_sample_path('contrib/pagelabels.pdf')
        expected_labels = ['iii', 'iv', '1', '2', '1']

        with open(path, 'rb') as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)
            for (i, page) in enumerate(PDFPage.create_pages(doc)):
                assert page.label == expected_labels[i]
