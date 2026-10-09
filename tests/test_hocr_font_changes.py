"""Regressions for hOCR words spanning font and position changes."""

from io import BytesIO
from xml.etree import ElementTree

import pytest

from pdfminer.converter import HOCRConverter
from pdfminer.layout import LAParams, LTChar, LTPage, LTTextLineHorizontal
from pdfminer.pdfcolor import PDFColorSpace
from pdfminer.pdffont import PDFType1Font
from pdfminer.pdfinterp import PDFGraphicState, PDFResourceManager
from pdfminer.psparser import LIT


@pytest.mark.parametrize("change", ["font", "size", "baseline", "none"])
@pytest.mark.parametrize("suffix", ["B", "BC", "B C"])
def test_hocr_preserves_characters_after_style_change(change: str, suffix: str) -> None:
    """A style change must start a fresh, active word buffer."""
    manager = PDFResourceManager()
    regular = PDFType1Font(manager, {"BaseFont": LIT("Helvetica")})
    bold = PDFType1Font(manager, {"BaseFont": LIT("Helvetica-Bold")})
    line = LTTextLineHorizontal(0)
    for index, text in enumerate("A" + suffix):
        changed = index > 0
        font = bold if changed and change == "font" else regular
        size = 14 if changed and change == "size" else 12
        baseline = 10 if changed and change == "baseline" else 0
        char = LTChar(
            (1, 0, 0, 1, index * 10, baseline),
            font,
            size,
            1,
            0,
            text,
            0.5,
            0,
            PDFColorSpace("DeviceGray", 1),
            PDFGraphicState(),
        )
        line.add(char)
    line.analyze(LAParams())
    page = LTPage(1, (0, 0, 100, 100))
    page.add(line)
    output = BytesIO()
    converter = HOCRConverter(manager, output)
    converter.receive_layout(page)
    converter.close()
    root = ElementTree.fromstring(output.getvalue())
    words = [node for node in root.iter() if node.get("class") == "ocrx_word"]
    expected = ("A" + suffix).split() if change == "none" else ["A", *suffix.split()]
    assert [node.text for node in words] == expected
    assert "bbox 0 " in words[0].attrib["title"]
    if change != "none":
        assert "bbox 10 " in words[1].attrib["title"]
