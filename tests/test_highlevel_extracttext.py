import unittest

from helpers import absolute_sample_path
from pdfminer.high_level import extract_text


def run(sample_path):
    absolute_path = absolute_sample_path(sample_path)
    s = extract_text(absolute_path)
    return s


test_strings = {
    "simple1.pdf": "Hello \n\nWorld\n\nWorld\n\nHello \n\nH e l l o  \n\nH e l l o  \n\nW o r l d\n\nW o r l d\n\n\f",
    "simple2.pdf": "\f",
    "simple3.pdf": "HelloHello\n\nWorld\n\nWorld\n\n\f",
}


class TestExtractText(unittest.TestCase):
    def test_simple1(self):
        test_file = "simple1.pdf"
        s = run(test_file)
        self.assertEqual(s, test_strings[test_file])

    def test_simple2(self):
        test_file = "simple2.pdf"
        s = run(test_file)
        self.assertEqual(s, test_strings[test_file])

    def test_simple3(self):
        test_file = "simple3.pdf"
        s = run(test_file)
        self.assertEqual(s, test_strings[test_file])


if __name__ == "__main__":
    unittest.main()
