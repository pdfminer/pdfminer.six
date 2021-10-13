from nose.tools import assert_equal, raises

from helpers import absolute_sample_path
from pdfminer.pdfdocument import PDFDocument, PDFNoPageLabels
from pdfminer.pdfparser import PDFParser
from pdfminer.pdftypes import PDFObjectNotFound


class TestPdfDocument(object):

    @raises(PDFObjectNotFound)
    def test_get_zero_objid_raises_pdfobjectnotfound(self):
        with open(absolute_sample_path('simple1.pdf'), 'rb') as in_file:
            parser = PDFParser(in_file)
            doc = PDFDocument(parser)
            doc.getobj(0)

    def test_encrypted_no_id(self):
        # Some documents may be encrypted but not have an /ID key in
        # their trailer. Tests
        # https://github.com/pdfminer/pdfminer.six/issues/594
        path = absolute_sample_path('encryption/encrypted_doc_no_id.pdf')
        with open(path, 'rb') as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)
            assert_equal(doc.info,
                         [{'Producer': b'European Patent Office'}])

    def test_page_labels(self):
        path = absolute_sample_path('contrib/pagelabels.pdf')
        with open(path, 'rb') as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)
            assert_equal(
                list(doc.get_page_labels()),
                ['iii', 'iv', '1', '2', '1'])

    @raises(PDFNoPageLabels)
    def test_no_page_labels(self):
        path = absolute_sample_path('simple1.pdf')
        with open(path, 'rb') as fp:
            parser = PDFParser(fp)
            doc = PDFDocument(parser)
            doc.get_page_labels()
