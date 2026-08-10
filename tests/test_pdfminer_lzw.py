from pdfminer.lzw import lzwdecode


def _pack(codes, width=9):
    """Pack a sequence of codes MSB-first at a fixed bit width, matching
    LZWDecoder.readbits."""
    bits = "".join(format(c, "0{}b".format(width)) for c in codes)
    while len(bits) % 8:
        bits += "0"
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


class TestLZWDecoder:
    def test_valid_stream_decodes(self):
        # clear(256), 'A'(65), 'B'(66), end-of-data(257)
        data = _pack([256, 65, 66, 257])
        assert lzwdecode(data) == b"AB"

    def test_missing_clear_code_is_not_fatal(self):
        # A stream that never sends the clear code (256) leaves the table
        # uninitialised. This must degrade gracefully rather than raising an
        # uncaught IndexError from table[code].
        assert lzwdecode(b"\x00\x00") == b""

    def test_out_of_range_first_code_is_not_fatal(self):
        # First code after an initial clear must be a literal in the table; an
        # out-of-range code here is corrupt data, not an IndexError.
        data = _pack([256, 300])
        assert lzwdecode(data) == b""
