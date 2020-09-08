import unittest

from helpers import absolute_sample_path
from pdfminer.high_level import extract_pages
from pdfminer.layout import LTChar, LTTextBox


class TestFontSize(unittest.TestCase):
    def test_font_size(self):
        path = absolute_sample_path('font-size-test.pdf')
        for page in extract_pages(path):
            for text_box in page:
                if isinstance(text_box, LTTextBox):
                    for line in text_box:
                        possible_number = line.get_text().strip()
                        if possible_number.isdigit():
                            expected_size = int(possible_number)
    
                            for char in line:
                                if isinstance(char, LTChar):
                                    actual_size = int(round(char.size))
                                    print(char, actual_size, expected_size)
                                    assert expected_size == actual_size
                        else:
                            print(repr(line.get_text()))
