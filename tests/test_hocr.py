import io
import xml.etree.ElementTree as ET

import pytest

from pdfminer.high_level import extract_text, extract_text_to_fp
from pdfminer.layout import LAParams


def _text_pdf(text: str) -> bytes:
    """Create a one-page PDF with an explicit Unicode mapping for its text."""
    content = (
        b"BT /F1 12 Tf 20 100 Td <" + text.encode("latin-1").hex().encode() + b"> Tj ET"
    )
    cmap = (
        b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n"
        b"/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n"
        b"/CMapName /TestUnicode def /CMapType 2 def\n"
        b"1 begincodespacerange <00> <ff> endcodespacerange\n"
        b"1 beginbfrange <00> <ff> <0000> endbfrange\n"
        b"endcmap CMapName currentdict /CMap defineresource pop end end"
    )
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
        b"/Encoding /WinAnsiEncoding /ToUnicode 6 0 R >>",
        b"<< /Length "
        + str(len(content)).encode()
        + b" >>\nstream\n"
        + content
        + b"\nendstream",
        b"<< /Length "
        + str(len(cmap)).encode()
        + b" >>\nstream\n"
        + cmap
        + b"\nendstream",
    ]
    data = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets = []
    for number, obj in enumerate(objects, 1):
        offsets.append(len(data))
        data += str(number).encode() + b" 0 obj\n" + obj + b"\nendobj\n"
    xref = len(data)
    data += b"xref\n0 7\n0000000000 65535 f \n"
    data += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    data += (
        b"trailer\n<< /Size 7 /Root 1 0 R >>\nstartxref\n"
        + str(xref).encode()
        + b"\n%%EOF\n"
    )
    return data


def _hocr(text: str, strip_control: bool, codec: str) -> str:
    pdf = _text_pdf(text)
    assert extract_text(io.BytesIO(pdf)).strip() == text
    output = io.BytesIO() if codec else io.StringIO()
    extract_text_to_fp(
        io.BytesIO(pdf),
        output,
        output_type="hocr",
        codec=codec,
        laparams=LAParams(),
        strip_control=strip_control,
    )
    value = output.getvalue()
    return value.decode("utf-8") if isinstance(value, bytes) else value


@pytest.mark.parametrize(
    "text", ["ordinary", "A&P", "<A&P>", "<tag>42</tag>", "&amp;", "café", "'quotes\""]
)
@pytest.mark.parametrize("strip_control", [False, True])
@pytest.mark.parametrize("codec", ["utf-8", ""])
def test_hocr_literal_text(text: str, strip_control: bool, codec: str) -> None:
    root = ET.fromstring(_hocr(text, strip_control, codec))
    words = root.findall(".//{*}span[@class='ocrx_word']")
    assert len(words) == 1
    assert list(words[0]) == []
    assert words[0].text == text


@pytest.mark.parametrize("control", ["\x00", "\x01", "\x0b"])
@pytest.mark.parametrize("codec", ["utf-8", ""])
def test_hocr_strip_control(control: str, codec: str) -> None:
    value = _hocr(f"A{control}&P", True, codec)
    root = ET.fromstring(value)
    line = root.find(".//{*}span[@class='ocr_line']")
    assert line is not None
    assert "".join(line.itertext()) == "A&P"
    assert control not in value


@pytest.mark.parametrize("codec", ["utf-8", ""])
def test_hocr_preserve_control_when_disabled(codec: str) -> None:
    value = _hocr("A\x01&P", False, codec)
    assert "A\x01&amp;P" in value
