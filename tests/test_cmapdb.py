"""Test cmapdb module, particularly IdentityCMap decoding."""

import struct
from io import BytesIO

import pytest

from pdfminer.cmapdb import CMapParser, FileUnicodeMap, IdentityCMap, IdentityCMapByte


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (b"A", "A"),
        (b"\xe9", "\u00e9"),
        (b"\x00", "\x00"),
        (b"", ""),
        (b"\x00A", "A"),
        (b"\x00f\x00i", "fi"),
        (b"\xd8=\xde\x00", "\U0001f600"),
        (b"\x00A\x01", "A"),
    ],
)
def test_unicode_map_byte_destinations(code: bytes, expected: str) -> None:
    """Recover one-byte destinations without changing longer UTF-16BE strings."""
    cmap = FileUnicodeMap()
    cmap.add_cid2unichr(1, code)
    assert cmap.get_unichr(1) == expected


@pytest.mark.parametrize(
    "mapping",
    [
        b"2 beginbfchar <01> <41> <02> <0042> endbfchar",
        b"1 beginbfrange <01> <02> <41> endbfrange",
        b"1 beginbfrange <01> <02> [<41> <0042>] endbfrange",
    ],
)
def test_cmap_parser_single_byte_unicode_destinations(mapping: bytes) -> None:
    """Read single-byte destinations in character, range, and array mappings."""
    cmap = FileUnicodeMap()
    CMapParser(cmap, BytesIO(b"begincmap\n" + mapping + b"\nendcmap")).run()
    assert cmap.cid2unichr == {1: "A", 2: "B"}


def test_identity_cmap_odd_length_buffer():
    """
    Test that IdentityCMap.decode() handles odd-length buffers correctly.

    Regression test for issues #668, #785, #193 where struct.unpack()
    would fail with "unpack requires a buffer of N bytes" when the
    code buffer length was not evenly divisible by 2.
    """
    cmap = IdentityCMap()

    # Test with odd-length buffer (21 bytes)
    # This would previously raise: struct.error: unpack requires a buffer of 20 bytes
    odd_buffer = struct.pack(">10H", *range(10)) + b"\x00"
    assert len(odd_buffer) == 21

    result = cmap.decode(odd_buffer)
    assert len(result) == 10  # Should decode 10 shorts
    assert result == tuple(range(10))


def test_identity_cmap_even_length_buffer():
    """
    Test that IdentityCMap.decode() still works correctly with even-length buffers.

    Ensures the fix doesn't break existing functionality.
    """
    cmap = IdentityCMap()

    # Test with even-length buffer (20 bytes)
    even_buffer = struct.pack(">10H", *range(10))
    assert len(even_buffer) == 20

    result = cmap.decode(even_buffer)
    assert len(result) == 10
    assert result == tuple(range(10))


def test_identity_cmap_empty_buffer():
    """Test that IdentityCMap.decode() handles empty buffers."""
    cmap = IdentityCMap()

    empty_buffer = b""
    result = cmap.decode(empty_buffer)
    assert result == ()


def test_identity_cmap_single_byte_buffer():
    """
    Test that IdentityCMap.decode() handles single-byte buffers.

    A 1-byte buffer should return an empty tuple since n = 1 // 2 = 0.
    """
    cmap = IdentityCMap()

    single_byte = b"\x00"
    result = cmap.decode(single_byte)
    assert result == ()


def test_identity_cmap_byte_odd_length():
    """Test that IdentityCMapByte.decode() handles any length correctly."""
    cmap_byte = IdentityCMapByte()

    # Test with various lengths
    for length in [1, 5, 11, 13, 21, 255]:
        test_buffer = bytes(range(min(length, 256)))[:length]
        result = cmap_byte.decode(test_buffer)
        assert len(result) == length
        assert result == tuple(range(min(length, 256)))[:length]


def test_identity_cmap_various_odd_lengths():
    """
    Test IdentityCMap with various odd-length buffers.

    Comprehensive test to ensure the fix works for all odd lengths.
    """
    cmap = IdentityCMap()

    # Test various odd lengths: 3, 5, 7, 9, 11, 13, 15, 17, 19, 21
    for num_shorts in range(1, 11):
        buffer_size = num_shorts * 2 + 1  # Add 1 to make it odd

        # Create buffer with num_shorts shorts + 1 extra byte
        buffer = struct.pack(f">{num_shorts}H", *range(num_shorts)) + b"\x00"
        assert len(buffer) == buffer_size

        result = cmap.decode(buffer)
        assert len(result) == num_shorts
        assert result == tuple(range(num_shorts))


def test_identity_cmap_max_values():
    """Test IdentityCMap with maximum unsigned short values."""
    cmap = IdentityCMap()

    # Test with max unsigned short values (65535)
    max_values = [65535, 65534, 65533, 65532, 65531]
    buffer = struct.pack(f">{len(max_values)}H", *max_values)

    result = cmap.decode(buffer)
    assert len(result) == len(max_values)
    assert result == tuple(max_values)
