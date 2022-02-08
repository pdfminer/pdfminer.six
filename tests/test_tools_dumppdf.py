import unittest

import pytest

from helpers import absolute_sample_path
from tempfilepath import TemporaryFilePath
from tools import dumppdf


def run(filename, options=None):
    absolute_path = absolute_sample_path(filename)
    with TemporaryFilePath() as output_file_name:
        if options:
            s = 'dumppdf -o %s %s %s' % (output_file_name,
                                         options, absolute_path)
        else:
            s = 'dumppdf -o %s %s' % (output_file_name, absolute_path)

        dumppdf.main(s.split(' ')[1:])


class TestDumpPDF(unittest.TestCase):
    def test_simple1(self):
        run('simple1.pdf', '-t -a')

    def test_simple2(self):
        run('simple2.pdf', '-t -a')

    def test_jo(self):
        run('jo.pdf', '-t -a')

    def test_simple3(self):
        run('simple3.pdf', '-t -a')

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

    def test_simple1_raw(self):
        """Known issue: crash in dumpxml writing binary to text stream."""
        with pytest.raises(TypeError):
            run('simple1.pdf', '-r -a')

    def test_simple1_binary(self):
        """Known issue: crash in dumpxml writing binary to text stream."""
        with pytest.raises(TypeError):
            run('simple1.pdf', '-b -a')
