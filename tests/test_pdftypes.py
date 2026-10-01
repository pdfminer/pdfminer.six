import logging
import zlib

import pytest

from pdfminer import settings
from pdfminer.pdftypes import PDFException, PDFStream, decompress_corrupted
from pdfminer.psparser import LIT

_PAYLOAD = b"A compressed stream that remains readable after checksum damage. " * 4


def _damaged_checksum(data: bytes) -> bytes:
    return data[:-1] + bytes([data[-1] ^ 1])


def _flate_stream(data: bytes) -> PDFStream:
    return PDFStream({"Filter": LIT("FlateDecode")}, data)


def test_decompress_corrupted_valid_and_empty() -> None:
    assert decompress_corrupted(zlib.compress(_PAYLOAD)) == _PAYLOAD
    assert decompress_corrupted(b"") == b""


@pytest.mark.parametrize("length", [1, 2, 3])
def test_decompress_corrupted_short_input(length: int) -> None:
    assert decompress_corrupted(zlib.compress(_PAYLOAD)[:length]) == b""


def test_decompress_corrupted_truncated_checksum() -> None:
    assert decompress_corrupted(zlib.compress(_PAYLOAD)[:-2]) == _PAYLOAD


def test_decompress_corrupted_checksum_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    damaged = _damaged_checksum(zlib.compress(_PAYLOAD))
    with caplog.at_level(logging.WARNING, logger="pdfminer.pdftypes"):
        assert decompress_corrupted(damaged) == _PAYLOAD
    assert "Data-loss while decompressing corrupted data" in caplog.text


@pytest.mark.parametrize("trailing", [b"", b"x", b"xy"])
def test_decompress_corrupted_late_error_with_trailing_bytes(
    trailing: bytes, caplog: pytest.LogCaptureFixture
) -> None:
    damaged = _damaged_checksum(zlib.compress(_PAYLOAD)) + trailing
    with caplog.at_level(logging.WARNING, logger="pdfminer.pdftypes"):
        assert decompress_corrupted(damaged) == _PAYLOAD
    assert "Data-loss while decompressing corrupted data" in caplog.text


def test_decompress_corrupted_early_error_after_three_trailing_bytes() -> None:
    damaged = _damaged_checksum(zlib.compress(_PAYLOAD)) + b"xyz"
    with pytest.raises(zlib.error):
        decompress_corrupted(damaged)


def test_decompress_corrupted_bad_header_raises() -> None:
    data = b"\x00\x00" + zlib.compress(_PAYLOAD)[2:]
    with pytest.raises(zlib.error):
        decompress_corrupted(data)


def test_pdfstream_valid_and_corrupted_flate(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(settings, "STRICT", False)
    compressed = zlib.compress(_PAYLOAD)
    assert _flate_stream(compressed).get_data() == _PAYLOAD
    with caplog.at_level(logging.WARNING, logger="pdfminer.pdftypes"):
        assert _flate_stream(_damaged_checksum(compressed)).get_data() == _PAYLOAD
    assert "Data-loss while decompressing corrupted data" in caplog.text


def test_pdfstream_bad_header_nonstrict_and_strict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"\x00\x00" + zlib.compress(_PAYLOAD)[2:]
    monkeypatch.setattr(settings, "STRICT", False)
    assert _flate_stream(data).get_data() == b""
    monkeypatch.setattr(settings, "STRICT", True)
    with pytest.raises(PDFException, match="Invalid zlib bytes"):
        _flate_stream(data).get_data()
