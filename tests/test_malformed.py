import unittest

from pdfminer.layout import (
    LAParams,
    LTTextBoxHorizontal,
    LTTextBoxVertical,
)
from pdfminer.pdfpage import PDFPage
from pdfminer.converter import PDFPageAggregator
from pdfminer.pdfinterp import (
    PDFResourceManager, 
    PDFPageInterpreter
)

class TestMalformedLayout(unittest.TestCase):
    def test_malformed_horizontal_layout(self):
        """
        The page aggregator should separate the 3 horizontal lines in the sample PDF.
        This sample represents a malformed PDF as there are blank spaces inserted into the lines between non-empty text lines.
        """
        fp = open('samples/contrib/issue_449_malformed_horizontal.pdf', 'rb')
        rsrcmgr = PDFResourceManager()
        laparams = {
            'line_overlap': 0.5,
            'char_margin': 2.0,
            'word_margin': 0.1,
            'line_margin': 0.5,
            'boxes_flow': 0.5,
            'detect_vertical': False,
            'all_texts': False
        }
        laparams = LAParams(**laparams)
        device = PDFPageAggregator(rsrcmgr, laparams=laparams)
        interpreter = PDFPageInterpreter(rsrcmgr, device)

        page = list(PDFPage.get_pages(fp))[0]
        interpreter.process_page(page)
        data = device.get_result()
        self.assertEqual(len([textbox for textbox in data if isinstance(textbox, LTTextBoxHorizontal)]), 3)

    def test_malformed_vertical_layout(self):
        """
        The page aggregator should separate the 3 horizontal lines in the sample PDF.
        This sample represents a malformed PDF as there are blank spaces inserted into the lines between non-empty text lines.
        """
        fp = open('samples/contrib/issue_449_malformed_vertical.pdf', 'rb')
        rsrcmgr = PDFResourceManager()
        laparams = {
            'line_overlap': 0.5,
            'char_margin': 2.0,
            'word_margin': 0.1,
            'line_margin': 0.5,
            'boxes_flow': 0.5,
            'detect_vertical': True,
            'all_texts': False
        }
        laparams = LAParams(**laparams)
        device = PDFPageAggregator(rsrcmgr, laparams=laparams)
        interpreter = PDFPageInterpreter(rsrcmgr, device)

        page = list(PDFPage.get_pages(fp))[0]
        interpreter.process_page(page)
        data = device.get_result()
        self.assertEqual(len([textbox for textbox in data if isinstance(textbox, LTTextBoxVertical)]), 3)
