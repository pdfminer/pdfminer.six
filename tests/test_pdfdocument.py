import unittest

from helpers import absolute_sample_path
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfparser import PDFParser
from pdfminer.pdftypes import PDFObjectNotFound


class TestPdfDocument(unittest.TestCase):

    def test_get_zero_objid_raises_pdfobjectnotfound(self):
        with open(absolute_sample_path('simple1.pdf'), 'rb') as in_file:
            parser = PDFParser(in_file)
            doc = PDFDocument(parser)
            self.assertRaises(PDFObjectNotFound, doc.getobj, 0)
