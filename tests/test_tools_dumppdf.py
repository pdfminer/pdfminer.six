import unittest

import warnings
from tempfile import NamedTemporaryFile

from helpers import absolute_sample_path
from pdfminer.pdfdocument import PDFNoValidXRefWarning
from tools import dumppdf


def run(filename, options=None):
    absolute_path = absolute_sample_path(filename)
    with NamedTemporaryFile() as output_file:
        if options:
            s = 'dumppdf -o %s %s %s' % (output_file.name,
                                         options, absolute_path)
        else:
            s = 'dumppdf -o %s %s' % (output_file.name, absolute_path)
        dumppdf.main(s.split(' ')[1:])


class TestDumpPDF(unittest.TestCase):
    def test_simple1(self):
        """dumppdf.py simple1.pdf raises a warning because it has no xref"""
        with warnings.catch_warnings(record=True) as ws:
            run('simple1.pdf', '-t -a')
            assert any(w.category == PDFNoValidXRefWarning for w in ws)

    def test_simple2(self):
        run('simple2.pdf', '-t -a')

    def test_jo(self):
        run('jo.pdf', '-t -a')

    def test_simple3(self):
        """dumppdf.py simple3.pdf raises a warning because it has no xref"""
        with warnings.catch_warnings(record=True) as ws:
            run('simple3.pdf', '-t -a')
            assert any(w.category == PDFNoValidXRefWarning for w in ws)

    def test_2(self):
        run('nonfree/dmca.pdf', '-t -a')

    def test_3(self):
        run('nonfree/f1040nr.pdf')

    def test_4(self):
        run('nonfree/i1040nr.pdf')

    def test_5(self):
        run('nonfree/kampo.pdf', '-t -a')

    def test_6(self):
        run('nonfree/naacl06-shinyama.pdf', '-t -a')
