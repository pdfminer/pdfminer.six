import io
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest

from pdfminer.converter import HTMLConverter
from pdfminer.high_level import extract_text_to_fp
from pdfminer.layout import (
    LAParams,
    LTChar,
    LTFigure,
    LTPage,
    LTTextBoxHorizontal,
    LTTextLineHorizontal,
)
from pdfminer.pdfcolor import PDFColorSpace
from pdfminer.pdffont import PDFFont
from pdfminer.pdfinterp import PDFGraphicState, PDFResourceManager
from tools import pdf2txt


class TextSpans(HTMLParser):
    """Read text and CSS properties from spans, excluding empty borders."""

    def __init__(self) -> None:
        """Track open spans and their text."""
        super().__init__(convert_charrefs=True)
        self.spans: list[tuple[dict[str, str], list[str]]] = []
        self.stack: list[tuple[dict[str, str], list[str]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Collect style properties when a span opens."""
        if tag == "span":
            properties = (dict(attrs).get("style") or "").split(";")
            style = dict(p.split(":", 1) for p in properties if ":" in p)
            span: tuple[dict[str, str], list[str]] = (
                {k.strip(): v.strip() for k, v in style.items()},
                [],
            )
            self.spans.append(span)
            self.stack.append(span)

    def handle_endtag(self, tag: str) -> None:
        """Stop collecting text when the current span closes."""
        if tag == "span" and self.stack:
            self.stack.pop()

    def handle_data(self, data: str) -> None:
        """Append decoded text to the innermost span."""
        if self.stack:
            self.stack[-1][1].append(data)


def text_spans(html: str) -> list[tuple[dict[str, str], str]]:
    """Return the style and decoded text of each nonempty span."""
    parser = TextSpans()
    parser.feed(html)
    return [(style, "".join(text)) for style, text in parser.spans if text]


def text_page(*names: str | bytes, text: str = "A") -> LTPage:
    """Build a layout with known font names, character sizes and positions."""
    line = LTTextLineHorizontal(0.5)
    for index, name in enumerate(names):
        font = PDFFont(
            {"FontName": name, "Descent": -200, "FontBBox": (0, -200, 1000, 800)},
            {},
            default_width=500,
        )
        line.add(
            LTChar(
                (1, 0, 0, 1, 10 + index * 20, 50),
                font,
                12,
                1,
                0,
                text if len(names) == 1 else chr(65 + index),
                0.5,
                0,
                PDFColorSpace("DeviceGray", 1),
                PDFGraphicState(),
            )
        )
    box = LTTextBoxHorizontal()
    box.index = 0
    box.add(line)
    page = LTPage(1, (0, 0, 200, 100))
    page.add(box)
    return page


def render_html(
    page: LTPage,
    converter: type[HTMLConverter] = HTMLConverter,
    *,
    binary: bool = False,
    **kwargs: Any,
) -> str:
    """Render a layout to a text or binary HTML stream."""
    out: io.BytesIO | io.StringIO = io.BytesIO() if binary else io.StringIO()
    device = converter(
        PDFResourceManager(),
        out,
        codec="utf-8" if binary else "",
        layoutmode=kwargs.pop("layoutmode", "exact"),
        showpageno=False,
        **kwargs,
    )
    device.receive_layout(page)
    device.close()
    value = out.getvalue()
    return value.decode("utf-8") if isinstance(value, bytes) else value


@pytest.mark.parametrize(
    ("name", "family"),
    [
        ("Helvetica", "Helvetica"),
        ("ABCDEF+Palatino-Bold", "Palatino-Bold"),
        (b"ABCDEF+Courier", "Courier"),
    ],
)
@pytest.mark.parametrize("scale", [1.0, 2.0])
@pytest.mark.parametrize("binary", [False, True])
def test_exact_font_and_geometry(
    name: str | bytes, family: str, scale: float, binary: bool
) -> None:
    spans = text_spans(
        render_html(text_page(name), scale=scale, fontscale=1.5, binary=binary)
    )
    assert len(spans) == 1
    style, text = spans[0]
    assert text == "A"
    assert style["font-family"] == family
    assert style["position"] == "absolute"
    assert style["color"] == "black"
    assert float(style["left"].removesuffix("px")) == pytest.approx(10 * scale)
    assert float(style["top"].removesuffix("px")) == pytest.approx(90.4 * scale)
    assert float(style["font-size"].removesuffix("px")) == pytest.approx(18 * scale)


@pytest.mark.parametrize("mode", ["exact", "normal", "loose"])
def test_character_font_changes(mode: str) -> None:
    html = render_html(text_page("ABCDEF+Helvetica-Bold", b"Courier"), layoutmode=mode)
    assert [(text, style["font-family"]) for style, text in text_spans(html)] == [
        ("A" if mode == "exact" else "A ", "Helvetica-Bold"),
        ("B", "Courier"),
    ]
    if mode != "exact":
        assert (
            '<span style="font-family: Helvetica-Bold; font-size:12.0px">A </span>'
            '<span style="font-family: Courier; font-size:12.0px">B'
        ) in html
        assert ("<br>" in html) == (mode == "normal")


def test_direct_place_text_without_font() -> None:
    out = io.StringIO()
    device = HTMLConverter(PDFResourceManager(), out, codec="")
    device.place_text("char", "X", 10, 20, 12)
    spans = text_spans(out.getvalue())
    assert len(spans) == 1 and spans[0][1] == "X"
    assert "font-family" not in spans[0][0]


def test_existing_place_text_override() -> None:
    class CustomConverter(HTMLConverter):
        """Delegate using the existing place_text argument list."""

        def place_text(
            self, color: str, text: str, x: float, y: float, size: float
        ) -> None:
            """Delegate without changing the original method signature."""
            super().place_text(color, text, x, y, size)

    spans = text_spans(render_html(text_page("Helvetica", "Courier"), CustomConverter))
    assert [(text, style["font-family"]) for style, text in spans] == [
        ("A", "Helvetica"),
        ("B", "Courier"),
    ]


@pytest.mark.parametrize("previous_font", [None, ("Existing", 10.0)])
def test_font_restored_after_character_output_failure(
    previous_font: tuple[str, float] | None,
) -> None:
    class FailingConverter(HTMLConverter):
        """Simulate an output failure during a character, after the box label."""

        def place_text(
            self, color: str, text: str, x: float, y: float, size: float
        ) -> None:
            """Raise only for character output."""
            if color == "char":
                raise RuntimeError("Character output failed")
            super().place_text(color, text, x, y, size)

    device = FailingConverter(
        PDFResourceManager(), io.StringIO(), codec="", layoutmode="exact"
    )
    device._font = previous_font
    with pytest.raises(RuntimeError, match="Character output failed"):
        device.receive_layout(text_page("Helvetica"))
    assert device._font == previous_font


def test_debug_label_has_no_character_font() -> None:
    spans = text_spans(render_html(text_page("Helvetica"), debug=1))
    assert spans[0][1] == "1"
    assert "font-family" not in spans[0][0]
    assert spans[1][0]["font-family"] == "Helvetica"


def test_disabled_character_output() -> None:
    assert text_spans(render_html(text_page("Helvetica"), text_colors={})) == []


def test_character_text_escaping() -> None:
    html = render_html(text_page("Helvetica", text="<&"))
    assert "&lt;&amp;" in html
    assert text_spans(html)[0][1] == "<&"


def test_font_attribute_escaping() -> None:
    html = render_html(text_page('ABCDEF+A"B&Name'))
    assert "A&quot;B&amp;Name" in html
    assert text_spans(html)[0][0]["font-family"] == 'A"B&Name'


@pytest.mark.parametrize("in_figure", [False, True])
def test_fonts_across_figures_and_pages(in_figure: bool) -> None:
    page = text_page("Helvetica-Bold", "Courier")
    if in_figure:
        figure = LTFigure("fonts", (0, 0, 200, 100), (1, 0, 0, 1, 0, 0))
        for item in page:
            figure.add(item)
        page = LTPage(1, (0, 0, 200, 100))
        page.add(figure)
    out = io.StringIO()
    device = HTMLConverter(
        PDFResourceManager(), out, codec="", layoutmode="exact", showpageno=False
    )
    device.receive_layout(page)
    assert device._font is None and device._fontstack == []
    device.receive_layout(text_page("Times-Roman"))
    assert device._font is None and device._fontstack == []
    assert [style["font-family"] for style, _ in text_spans(out.getvalue())] == [
        "Helvetica-Bold",
        "Courier",
        "Times-Roman",
    ]


def two_font_pdf() -> bytes:
    """Create a small independent PDF using two standard fonts and a valid xref."""
    content = b"BT /F1 12 Tf 10 50 Td (A) Tj /F2 12 Tf 20 0 Td (B) Tj ET\n"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 100] "
        b"/Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> /Contents 4 0 R >>",
        b"<< /Length "
        + str(len(content)).encode()
        + b" >>\nstream\n"
        + content
        + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
    ]
    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(pdf))
        pdf.extend(f"{number} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode())
    pdf.extend(
        (
            f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode()
    )
    return bytes(pdf)


@pytest.mark.parametrize("mode", ["exact", "normal", "loose"])
def test_font_names_through_high_level_api(mode: str) -> None:
    out = io.BytesIO()
    extract_text_to_fp(
        io.BytesIO(two_font_pdf()),
        out,
        output_type="html",
        layoutmode=mode,
        laparams=LAParams(word_margin=0),
    )
    assert [
        style["font-family"] for style, _ in text_spans(out.getvalue().decode())
    ] == [
        "Helvetica-Bold",
        "Courier",
    ]


def test_font_names_through_cli(tmp_path: Path) -> None:
    infile = tmp_path / "two_fonts.pdf"
    outfile = tmp_path / "two_fonts.html"
    infile.write_bytes(two_font_pdf())
    assert (
        pdf2txt.main([str(infile), "-o", str(outfile), "-t", "html", "-Y", "exact"])
        == 0
    )
    assert [
        style["font-family"]
        for style, _ in text_spans(outfile.read_text(encoding="utf-8"))
    ] == [
        "Helvetica-Bold",
        "Courier",
    ]
