from nose.tools import raises
from pdfminer.pdftypes import PDFObjectNotFound

from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfparser import PDFParser


class TestPdfDocument(object):

    @raises(PDFObjectNotFound)
    def test_get_zero_objid_raises_pdfobjectnotfound(self):
        with open('../samples/simple1.pdf', 'rb') as in_file:
            parser = PDFParser(in_file)
            doc = PDFDocument(parser)
            doc.getobj(0)