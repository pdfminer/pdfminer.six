from nose.tools import assert_equal

from helpers import absolute_sample_path
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfpage import PDFPage


class TestPdfPage(object):
    def test_page_labels(self):
        path = absolute_sample_path('contrib/pagelabels.pdf')
        expected_labels = ['iii', 'iv', '1', '2', '1']

        with open(path, 'rb') as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)
            for (i, page) in enumerate(PDFPage.create_pages(doc)):
                assert_equal(page.label, expected_labels[i])
