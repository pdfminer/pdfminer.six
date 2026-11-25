import logging
from tempfile import TemporaryDirectory

from pdfminer.image import ImageWriter


class _FakeStream:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def get_data(self) -> bytes:
        return self._data


class _FakeImage:
    """Minimal stand-in for LTImage with the attributes _save_raw uses."""

    def __init__(self) -> None:
        self.name = "img-unknown"
        self.bits = 8
        self.srcsize = (2, 2)
        self.stream = _FakeStream(b"\x00\x01\x02\x03")


def test_save_raw_warns_about_unknown_encoding(caplog):
    with TemporaryDirectory() as outdir:
        writer = ImageWriter(outdir)
        with caplog.at_level(logging.WARNING, logger="pdfminer.image"):
            name = writer._save_raw(_FakeImage())

    assert name.endswith(".img")
    assert any(
        record.levelno == logging.WARNING and "img-unknown" in record.getMessage()
        for record in caplog.records
    )
