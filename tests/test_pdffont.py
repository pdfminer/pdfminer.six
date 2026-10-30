from typing import Any

import pytest

from pdfminer.converter import PDFPageAggregator
from pdfminer.layout import LAParams
from pdfminer.pdffont import PDFCIDFont, PDFFont, PDFFontError, get_widths
from pdfminer.pdfinterp import PDFPageInterpreter, PDFResourceManager
from pdfminer.pdftypes import PDFObjRef, PDFStream
from pdfminer.psparser import PSLiteral
from tests.helpers import absolute_sample_path


def test_get_cmap():
    """Test if cmap file is read from pdfminer/cmap

    Regression test for https://github.com/pdfminer/pdfminer.six/issues/391
    """
    cmap_name = "UniGB-UCS2-H"
    spec = {"Encoding": PSLiteral(cmap_name)}
    resource_manager = PDFResourceManager()
    font = PDFCIDFont(resource_manager, spec)

    cmap = font.get_cmap_from_spec(spec, False)

    assert cmap.attrs.get("CMapName") == cmap_name
    assert len(cmap.code2cid) > 0


class MockPdfFont(PDFFont):
    def to_unichr(self, cid: int) -> str:
        return str(cid)


@pytest.mark.parametrize(
    ("msg", "widths", "expected"),
    [
        ("No widths should use default", {}, 0.1),
        ("Int cid widths should be used", {0: 50.0}, 0.05),
        ("Str cid widths should be used", {"0": 200.0}, 0.2),
        ("Invalid cid widths should use default", {0: None}, 0.1),
        ("Invalid cid widths should use default", {"0": None}, 0.1),
    ],
)
def test_pdffont_char_width_defaults(
    msg: str, widths: dict[str | int, float], expected: float
) -> None:
    pdffont = MockPdfFont(descriptor={}, widths=widths, default_width=100.0)

    assert pdffont.char_width(0) == expected, msg


def test_pdffont_get_widths():
    assert get_widths([0, [1, 2, 3, 4]]) == {0: 1, 1: 2, 2: 3, 3: 4}
    assert get_widths([0, 4, 3]) == {0: 3, 1: 3, 2: 3, 3: 3, 4: 3}


def test_pdffont_get_widths_object_ref():
    """Regression test for https://github.com/pdfminer/pdfminer.six/issues/629"""

    class MockDoc:
        def getobj(self, objid: int) -> Any:
            return [1, 2, 3, 4]

    obj = PDFObjRef(doc=MockDoc(), objid=121)
    assert get_widths([0, obj]) == {0: 1, 1: 2, 2: 3, 3: 4}


def test_cmap_font_12():
    from collections.abc import Generator

    from pdfminer.pdfpage import PDFPage

    def pdf_to_pages(file_name: str) -> Generator[PDFPage, None, None]:
        from pdfminer.pdfpage import PDFPage

        with open(file_name, "rb") as fp:
            yield from PDFPage.get_pages(fp)

    pdf_rm = PDFResourceManager()
    pdf_param = LAParams(
        detect_vertical=True, char_margin=1, all_texts=True, boxes_flow=None
    )
    pdf_device = PDFPageAggregator(pdf_rm, laparams=pdf_param)
    pdf_interpreter = PDFPageInterpreter(pdf_rm, pdf_device)
    for pdf_page in pdf_to_pages(
        absolute_sample_path("contrib/issue-598-cmap-other-fonts.pdf")
    ):
        pdf_interpreter.process_page(pdf_page)

    assert pdf_device.get_result() is not None


EMBEDDED_CMAP_STREAM = b"""\
/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> def
/CMapName /ArbolCustom-H def
/CMapType 2 def
1 begincodespacerange
<00> <FF>
endcodespacerange
1 begincidchar
<01> 5
endcidchar
1 begincidrange
<10> <12> 20
endcidrange
endcmap
CMapName currentdict /CMap defineresource pop
end
end
"""


def embedded_encoding_spec(data: bytes) -> dict[str, Any]:
    return {
        "Encoding": PDFStream({"CMapName": PSLiteral("ArbolCustom-H")}, data),
    }


def test_get_cmap_from_embedded_encoding_stream():
    """An Encoding that is an embedded CMap stream supplies the mapping.

    Generators such as Prince XML embed a custom CMap as a stream whose
    name is not in the predefined database. The code-to-CID mapping lives
    in the stream itself; without reading it, decode() yields nothing
    and every character in the font is silently dropped.
    """
    spec = embedded_encoding_spec(EMBEDDED_CMAP_STREAM)
    font = PDFCIDFont(PDFResourceManager(), spec)

    cmap = font.get_cmap_from_spec(spec, False)

    assert list(cmap.decode(b"\x01")) == [5]
    assert list(cmap.decode(b"\x10\x11\x12")) == [20, 21, 22]


def test_get_cmap_from_embedded_encoding_stream_wmode():
    """The WMode of an embedded CMap carries over to the parsed CMap."""
    data = EMBEDDED_CMAP_STREAM.replace(
        b"/CMapType 2 def", b"/CMapType 2 def\n/WMode 1 def"
    )
    spec = embedded_encoding_spec(data)
    font = PDFCIDFont(PDFResourceManager(), spec)

    cmap = font.get_cmap_from_spec(spec, False)

    assert cmap.is_vertical()


def test_get_cmap_unknown_name_without_stream_still_falls_back():
    """Behaviour for unknown predefined names is unchanged."""
    spec = {"Encoding": PSLiteral("NoSuchCMap-H")}
    font = PDFCIDFont(PDFResourceManager(), spec)

    cmap = font.get_cmap_from_spec(spec, False)
    assert list(cmap.decode(b"\x01")) == []

    with pytest.raises(PDFFontError):
        font.get_cmap_from_spec(spec, True)


def test_get_cmap_embedded_stream_without_mappings_falls_back():
    """An embedded stream with no cid sections changes nothing."""
    spec = embedded_encoding_spec(b"this is not a CMap stream")
    font = PDFCIDFont(PDFResourceManager(), spec)

    cmap = font.get_cmap_from_spec(spec, False)

    assert list(cmap.decode(b"\x01")) == []


def test_get_cmap_embedded_stream_oversized_range_falls_back():
    """A begincidrange that expands past the mapping bound is ignored."""
    data = EMBEDDED_CMAP_STREAM.replace(b"<10> <12> 20", b"<000000> <FFFFFF> 20")
    spec = embedded_encoding_spec(data)
    font = PDFCIDFont(PDFResourceManager(), spec)

    cmap = font.get_cmap_from_spec(spec, False)

    # The oversized range discards the whole embedded CMap, including
    # the otherwise valid begincidchar entry: decoding must not proceed
    # with a partial mapping.
    assert list(cmap.decode(b"\x10")) == []
    assert list(cmap.decode(b"\x01")) == []


def test_type0_font_with_embedded_encoding_stream_decodes_to_text():
    """End to end: Type0 font, embedded Encoding stream, ToUnicode map."""
    encoding_cmap = b"""\
/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
/CMapName /ArbolCustom-H def
1 begincodespacerange
<0000> <FFFF>
endcodespacerange
1 begincidrange
<0001> <0003> 1
endcidrange
endcmap
CMapName currentdict /CMap defineresource pop
end
end
"""
    tounicode_cmap = b"""\
/CIDInit /ProcSet findresource begin
12 dict begin
begincmap
1 begincodespacerange
<0000> <FFFF>
endcodespacerange
3 beginbfchar
<0001> <0041>
<0002> <0042>
<0003> <0043>
endbfchar
endcmap
CMapName currentdict /CMap defineresource pop
end
end
"""
    descendant = {
        "BaseFont": PSLiteral("ArbolCustom"),
        "Subtype": PSLiteral("CIDFontType2"),
        "CIDSystemInfo": {
            "Registry": b"Adobe",
            "Ordering": b"Identity",
            "Supplement": 0,
        },
        "FontDescriptor": {},
        "DW": 1000,
    }
    spec = {
        "Type": PSLiteral("Font"),
        "Subtype": PSLiteral("Type0"),
        "BaseFont": PSLiteral("ArbolCustom"),
        "Encoding": PDFStream({"CMapName": PSLiteral("ArbolCustom-H")}, encoding_cmap),
        "DescendantFonts": [descendant],
        "ToUnicode": PDFStream({}, tounicode_cmap),
    }

    font = PDFResourceManager().get_font(None, spec)

    cids = list(font.decode(b"\x00\x01\x00\x02\x00\x03"))
    assert cids == [1, 2, 3]
    assert "".join(font.to_unichr(cid) for cid in cids) == "ABC"
