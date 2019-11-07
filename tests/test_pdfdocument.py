from nose.tools import raises

from helpers import absolute_sample_path
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfparser import PDFParser
from pdfminer.pdftypes import PDFObjectNotFound


class TestPdfDocument(object):

    @raises(PDFObjectNotFound)
    def test_get_zero_objid_raises_pdfobjectnotfound(self):
        with open(absolute_sample_path('simple1.pdf'), 'rb') as in_file:
            parser = PDFParser(in_file)
            doc = PDFDocument(parser)
            doc.getobj(0)
