import struct

from pdfminer.pdftypes import uint_value


def test_uint_value_zero_stays_zero():
    # A permission field of 0 is unsigned 0. The old check treated 0 as
    # negative, so uint_value(0, 32) was 2**32 and struct.pack("<L", ...) failed.
    assert uint_value(0, 32) == 0
    assert struct.pack("<L", uint_value(0, 32)) == b"\x00\x00\x00\x00"
    assert uint_value(-1, 32) == 2**32 - 1
    assert uint_value(-44, 32) == 2**32 - 44
    assert uint_value(4, 32) == 4
