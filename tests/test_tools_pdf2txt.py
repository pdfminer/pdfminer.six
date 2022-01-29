import os
from shutil import rmtree
from tempfile import mkdtemp
import filecmp

import tools.pdf2txt as pdf2txt
from helpers import absolute_sample_path
from tempfilepath import TemporaryFilePath


def run(sample_path, options=None):
    absolute_path = absolute_sample_path(sample_path)
    with TemporaryFilePath() as output_file_name:
        if options:
            s = 'pdf2txt -o{} {} {}' \
                .format(output_file_name, options, absolute_path)
        else:
            s = 'pdf2txt -o{} {}'.format(output_file_name, absolute_path)

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
        run('nonfree/f1040nr.pdf', '-p 1')

    def test_nonfree_i1040nr(self):
        run('nonfree/i1040nr.pdf', '-p 1')

    def test_nonfree_kampo(self):
        run('nonfree/kampo.pdf')

    def test_nonfree_naacl06_shinyama(self):
        run('nonfree/naacl06-shinyama.pdf')

    def test_nlp2004slides(self):
        run('nonfree/nlp2004slides.pdf', '-p 1')

    def test_contrib_2b(self):
        run('contrib/2b.pdf', '-A -t xml')

    def test_contrib_issue_350(self):
        """Regression test for
        https://github.com/pdfminer/pdfminer.six/issues/350"""
        run('contrib/issue-00352-asw-oct96-p41.pdf')

    def test_scancode_patchelf(self):
        """Regression test for https://github.com/euske/pdfminer/issues/96"""
        run('scancode/patchelf.pdf')

    def test_contrib_hash_two_complement(self):
        """Check that unsigned integer is added correctly to encryption hash.et

        See https://github.com/pdfminer/pdfminer.six/issues/186
        """
        run('contrib/issue-00352-hash-twos-complement.pdf')

    def test_contrib_excel(self):
        """Regression test for
         https://github.com/pdfminer/pdfminer.six/issues/369
         """
        run('contrib/issue-00369-excel.pdf', '-t html')

    def test_encryption_aes128(self):
        run('encryption/aes-128.pdf', '-P foo')

    def test_encryption_aes128m(self):
        run('encryption/aes-128-m.pdf', '-P foo')

    def test_encryption_aes256(self):
        run('encryption/aes-256.pdf', '-P foo')

    def test_encryption_aes256m(self):
        run('encryption/aes-256-m.pdf', '-P foo')

    def test_encryption_aes256_r6_user(self):
        run('encryption/aes-256-r6.pdf', '-P usersecret')

    def test_encryption_aes256_r6_owner(self):
        run('encryption/aes-256-r6.pdf', '-P ownersecret')

    def test_encryption_base(self):
        run('encryption/base.pdf', '-P foo')

    def test_encryption_rc4_40(self):
        run('encryption/rc4-40.pdf', '-P foo')

    def test_encryption_rc4_128(self):
        run('encryption/rc4-128.pdf', '-P foo')


class TestDumpImages:

    @staticmethod
    def extract_images(input_file, *args):
        output_dir = mkdtemp()
        with TemporaryFilePath() as output_file_name:
            commands = ['-o', output_file_name, '--output-dir',
                        output_dir, input_file, *args]
            pdf2txt.main(commands)
        image_files = os.listdir(output_dir)
        rmtree(output_dir)
        return image_files

    def test_nonfree_dmca(self):
        """Extract images of pdf containing bmp images

        Regression test for:
        https://github.com/pdfminer/pdfminer.six/issues/131
        """
        filepath = absolute_sample_path('../samples/nonfree/dmca.pdf')
        image_files = self.extract_images(filepath, '-p', '1')
        assert image_files[0].endswith('bmp')

    def test_nonfree_175(self):
        """Extract images of pdf containing jpg images"""
        self.extract_images(absolute_sample_path('../samples/nonfree/175.pdf'))

    def test_jbig2_image_export(self):
        """Extract images of pdf containing jbig2 images

        Feature test for: https://github.com/pdfminer/pdfminer.six/pull/46
        """
        input_file = absolute_sample_path(
            '../samples/contrib/pdf-with-jbig2.pdf')
        output_dir = mkdtemp()
        with TemporaryFilePath() as output_file_name:
            commands = ['-o', output_file_name, '--output-dir',
                        output_dir, input_file]
            pdf2txt.main(commands)
        image_files = os.listdir(output_dir)
        try:
            assert image_files[0].endswith('.jb2')
            assert filecmp.cmp(output_dir + '/' + image_files[0],
                               absolute_sample_path(
                                   '../samples/contrib/XIPLAYER0.jb2'))
        finally:
            rmtree(output_dir)

    def test_contrib_matplotlib(self):
        """Test a pdf with Type3 font"""
        run('contrib/matplotlib.pdf')

    def test_nonfree_cmp_itext_logo(self):
        """Test a pdf with Type3 font"""
        run('nonfree/cmp_itext_logo.pdf')
