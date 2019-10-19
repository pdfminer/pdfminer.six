import os
from shutil import rmtree
from tempfile import NamedTemporaryFile, mkdtemp

import nose

import tools.pdf2txt as pdf2txt


def full_path(relative_path_to_this_file):
    this_file_dir = os.path.dirname(os.path.abspath(__file__))
    abspath = os.path.abspath(os.path.join(this_file_dir, relative_path_to_this_file))
    return abspath


def run(datapath, filename, options=None):
    i = full_path(datapath + filename + '.pdf')
    o = full_path(filename + '.txt')
    if options:
        s = 'pdf2txt -o{} {} {}'.format(o, options, i)
    else:
        s = 'pdf2txt -o{} {}'.format(o, i)
    pdf2txt.main(s.split(' ')[1:])


class TestDumpPDF():

    def test_1(self):
        run('../samples/', 'jo')
        run('../samples/', 'simple1')
        run('../samples/', 'simple2')
        run('../samples/', 'simple3')
        run('../samples/','sampleOneByteIdentityEncode')

    def test_2(self):
        run('../samples/nonfree/', 'dmca')

    def test_3(self):
        run('../samples/nonfree/', 'f1040nr')

    def test_4(self):
        run('../samples/nonfree/', 'i1040nr')

    def test_5(self):
        run('../samples/nonfree/', 'kampo')

    def test_6(self):
        run('../samples/nonfree/', 'naacl06-shinyama')

    # this test works on Windows but on Linux & Travis-CI it says
    # PDFSyntaxError: No /Root object! - Is this really a PDF?
    # TODO: Find why
    """
    def test_7(self):
        run('../samples/contrib/','stamp-no')
    """

    def test_8(self):
        run('../samples/contrib/', '2b', '-A -t xml')

    def test_9(self):
        run('../samples/nonfree/', '175')  # https://github.com/pdfminer/pdfminer.six/issues/65

    def test_10(self):
        run('../samples/scancode/', 'patchelf')  # https://github.com/euske/pdfminer/issues/96


class TestDumpImages(object):

    def extract_images(self, input_file):
        output_dir = mkdtemp()
        with NamedTemporaryFile() as output_file:
            commands = ['-o', output_file.name, '--output-dir', output_dir, input_file]
            pdf2txt.main(commands)
        image_files = os.listdir(output_dir)
        rmtree(output_dir)
        return image_files

    def test_nonfree_dmca(self):
        """Extract images of pdf containing bmp images

        Regression test for: https://github.com/pdfminer/pdfminer.six/issues/131
        """
        image_files = self.extract_images(full_path('../samples/nonfree/dmca.pdf'))
        assert image_files[0].endswith('bmp')

    def test_nonfree_175(self):
        """Extract images of pdf containing jpg images"""
        self.extract_images(full_path('../samples/nonfree/175.pdf'))


if __name__ == '__main__':
    nose.runmodule()
