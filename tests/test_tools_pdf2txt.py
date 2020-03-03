import os
from shutil import rmtree
from tempfile import NamedTemporaryFile, mkdtemp

import tools.pdf2txt as pdf2txt
from helpers import absolute_sample_path


def run(sample_path, options=None):
    absolute_path = absolute_sample_path(sample_path)
    with NamedTemporaryFile() as output_file:
        if options:
            s = 'pdf2txt -o{} {} {}' \
                .format(output_file.name, options, absolute_path)
        else:
            s = 'pdf2txt -o{} {}'.format(output_file.name, absolute_path)
        pdf2txt.main(s.split(' ')[1:])


class TestPdf2Txt():
    def test_jo(self):
        run('jo.pdf')

    def test_simple1(self):
        run('simple1.pdf')

    def test_simple2(self):
        run('simple2.pdf')

    def test_simple3(self):
        run('simple3.pdf')

    def test_sample_one_byte_identity_encode(self):
        run('sampleOneByteIdentityEncode.pdf')

    def test_nonfree_175(self):
        """Regression test for:
        https://github.com/pdfminer/pdfminer.six/issues/65
        """
        run('nonfree/175.pdf')

    def test_nonfree_dmca(self):
        run('nonfree/dmca.pdf')

    def test_nonfree_f1040nr(self):
        run('nonfree/f1040nr.pdf')

    def test_nonfree_i1040nr(self):
        run('nonfree/i1040nr.pdf')

    def test_nonfree_kampo(self):
        run('nonfree/kampo.pdf')

    def test_nonfree_naacl06_shinyama(self):
        run('nonfree/naacl06-shinyama.pdf')

    def test_nlp2004slides(self):
        run('nonfree/nlp2004slides.pdf')

    def test_contrib_2b(self):
        run('contrib/2b.pdf', '-A -t xml')

    def test_scancode_patchelf(self):
        """Regression test for # https://github.com/euske/pdfminer/issues/96"""
        run('scancode/patchelf.pdf')

    def test_contrib_hash_two_complement(self):
        """Check that unsigned integer is added correctly to encryption hash.

        See https://github.com/pdfminer/pdfminer.six/issues/186
        """
        run('contrib/issue-00352-hash-twos-complement.pdf')


class TestDumpImages:

    @staticmethod
    def extract_images(input_file):
        output_dir = mkdtemp()
        with NamedTemporaryFile() as output_file:
            commands = ['-o', output_file.name, '--output-dir',
                        output_dir, input_file]
            pdf2txt.main(commands)
        image_files = os.listdir(output_dir)
        rmtree(output_dir)
        return image_files

    def test_nonfree_dmca(self):
        """Extract images of pdf containing bmp images

        Regression test for:
        https://github.com/pdfminer/pdfminer.six/issues/131
        """
        image_files = self.extract_images(
            absolute_sample_path('../samples/nonfree/dmca.pdf'))
        assert image_files[0].endswith('bmp')

    def test_nonfree_175(self):
        """Extract images of pdf containing jpg images"""
        self.extract_images(absolute_sample_path('../samples/nonfree/175.pdf'))

    def test_jbig2_image_export(self):
        """Extract images of pdf containing jbig2 images

        Feature test for: https://github.com/pdfminer/pdfminer.six/pull/46
        """
        image_files = self.extract_images(
            absolute_sample_path('../samples/contrib/pdf-with-jbig2.pdf'))
        assert image_files[0].endswith('.jb2')

    def test_contrib_matplotlib(self):
        """Test a pdf with Type3 font"""
        run('contrib/matplotlib.pdf')

    def test_nonfree_cmp_itext_logo(self):
        """Test a pdf with Type3 font"""
        run('nonfree/cmp_itext_logo.pdf')
