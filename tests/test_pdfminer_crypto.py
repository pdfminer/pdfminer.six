"""Test of various compression/encoding modules (previously in doctests)
"""
import binascii
from nose.tools import assert_equal

from pdfminer.arcfour import Arcfour
from pdfminer.ascii85 import asciihexdecode, ascii85decode
from pdfminer.lzw import lzwdecode
from pdfminer.rijndael import RijndaelEncryptor
from pdfminer.runlength import rldecode


def hex(b):
    """encode('hex')"""
    return binascii.hexlify(b)


def dehex(b):
    """decode('hex')"""
    return binascii.unhexlify(b)


class TestAscii85():
    def test_ascii85decode(self):
        """The sample string is taken from:
        http://en.wikipedia.org/w/index.php?title=Ascii85"""
        assert_equal(ascii85decode(b'9jqo^BlbD-BleB1DJ+*+F(f,q'),
                     b'Man is distinguished')
        assert_equal(ascii85decode(b'E,9)oF*2M7/c~>'),
                     b'pleasure.')

    def test_asciihexdecode(self):
        assert_equal(asciihexdecode(b'61 62 2e6364   65'),
                     b'ab.cde')
        assert_equal(asciihexdecode(b'61 62 2e6364   657>'),
                     b'ab.cdep')
        assert_equal(asciihexdecode(b'7>'),
                     b'p')


class TestArcfour():
    def test(self):
        assert_equal(hex(Arcfour(b'Key').process(b'Plaintext')),
                     b'bbf316e8d940af0ad3')
        assert_equal(hex(Arcfour(b'Wiki').process(b'pedia')),
                     b'1021bf0420')
        assert_equal(hex(Arcfour(b'Secret').process(b'Attack at dawn')),
                     b'45a01f645fc35b383552544b9bf5')


class TestLzw():
    def test_lzwdecode(self):
        assert_equal(lzwdecode(b'\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01'),
                     b'\x2d\x2d\x2d\x2d\x2d\x41\x2d\x2d\x2d\x42')


class TestRunlength():
    def test_rldecode(self):
        assert_equal(rldecode(b'\x05123456\xfa7\x04abcde\x80junk'),
                     b'1234567777777abcde')


class TestRijndaelEncryptor():
    def test_RijndaelEncryptor(self):
        key = dehex(b'00010203050607080a0b0c0d0f101112')
        plaintext = dehex(b'506812a45f08c889b97f5980038b8359')
        assert_equal(hex(RijndaelEncryptor(key, 128).encrypt(plaintext)),
                     b'd8f532538289ef7d06b506a4fd5be9c9')
