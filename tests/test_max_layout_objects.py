"""Tests for LAParams.max_layout_objects.

The cap bounds how many non-text layout objects (paths, curves, images)
are retained per page, so pages crowded with vector graphics cannot grow
time and memory without bound. Text objects are never dropped.

Note on text comparisons: the order in which layout analysis emits text
boxes is not deterministic across runs (grouping tie-breaks on object
ids), so extracted text is compared as a multiset of lines, not bytewise.
"""

import io
from collections import Counter

import pytest

from pdfminer.converter import PDFPageAggregator
from pdfminer.high_level import extract_text
from pdfminer.layout import (
    LAParams,
    LTContainer,
    LTCurve,
    LTImage,
    LTItem,
    LTLine,
    LTPage,
    LTRect,
)
from pdfminer.pdfexceptions import PDFTypeError, PDFValueError
from pdfminer.pdfinterp import PDFPageInterpreter, PDFResourceManager
from pdfminer.pdfpage import PDFPage

NON_TEXT_TYPES = (LTLine, LTRect, LTCurve, LTImage)


def _segments(n: int) -> str:
    ops = ["0.5 w"]
    for i in range(n):
        x = 20 + (i % 100) * 5.5
        y = 20 + ((i // 100) % 140) * 5.4
        ops.append(f"{x:.1f} {y:.1f} m {x + 4:.1f} {y:.1f} l S")
    return "\n".join(ops)


def _labels(n: int, step: int = 50) -> str:
    ops = []
    for i in range(0, n, step):
        x = 20 + (i % 100) * 5.5
        y = 20 + ((i // 100) % 140) * 5.4
        ops.append(f"BT /F1 8 Tf 1 0 0 1 {x:.1f} {y + 6:.1f} Tm (L{i}) Tj ET")
    return "\n".join(ops)


def _assemble(objects: list[bytes]) -> bytes:
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref_pos = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n"
    ).encode()
    return bytes(out)


def _stream(data: str) -> bytes:
    raw = data.encode("ascii")
    return (
        b"<< /Length " + str(len(raw)).encode() + b" >>\nstream\n" + raw + b"endstream"
    )


def make_pdf(page_contents: list[str]) -> bytes:
    """A minimal PDF with one content stream per page and a Helvetica font."""
    n_pages = len(page_contents)
    kids = " ".join(f"{5 + 2 * i} 0 R" for i in range(n_pages))
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>".encode(),
        (
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
            b"/Encoding /WinAnsiEncoding >>"
        ),
        b"placeholder-font-slot",
    ]
    # objects list is 1-based; slot 3 is the font, slot 4 unused padding so
    # that page objects start at 5 as referenced above.
    objects[3] = b"<< /Type /Metadata >>"  # not referenced; keeps numbering
    for i, content in enumerate(page_contents):
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                f"/Resources << /Font << /F1 3 0 R >> >> "
                f"/Contents {6 + 2 * i} 0 R >>"
            ).encode()
        )
        objects.append(_stream(content))
    return _assemble(objects)


def make_pdf_with_form(n_form_paths: int) -> bytes:
    """One page: one text line plus a Form XObject with n_form_paths paths."""
    page_content = (
        "BT /F1 12 Tf 1 0 0 1 20 760 Tm (Hello form) Tj ET\nq 1 0 0 1 0 0 cm /Fm1 Do Q"
    )
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> /XObject << /Fm1 6 0 R >> >> "
            b"/Contents 5 0 R >>"
        ),
        (
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
            b"/Encoding /WinAnsiEncoding >>"
        ),
        _stream(page_content),
        (
            b"<< /Type /XObject /Subtype /Form /BBox [0 0 612 792] /Length "
            + str(len(_segments(n_form_paths).encode())).encode()
            + b" >>\nstream\n"
            + _segments(n_form_paths).encode()
            + b"endstream"
        ),
    ]
    return _assemble(objects)


def analyze_pages(pdf_bytes: bytes, laparams: LAParams) -> list[LTPage]:
    mgr = PDFResourceManager()
    device = PDFPageAggregator(mgr, laparams=laparams)
    interpreter = PDFPageInterpreter(mgr, device)
    trees: list[LTPage] = []
    with io.BytesIO(pdf_bytes) as f:
        for page in PDFPage.get_pages(f):
            interpreter.process_page(page)
            trees.append(device.get_result())
    return trees


def count_types(tree: LTPage) -> Counter[str]:
    counts: Counter[str] = Counter()

    def walk(item: LTItem) -> None:
        counts[type(item).__name__] += 1
        if isinstance(item, LTContainer):
            for child in item:
                walk(child)

    walk(tree)
    return counts


def non_text_count(tree: LTPage) -> int:
    total = 0

    def walk(item: LTItem) -> None:
        nonlocal total
        if isinstance(item, NON_TEXT_TYPES):
            total += 1
        if isinstance(item, LTContainer):
            for child in item:
                walk(child)

    walk(tree)
    return total


def sorted_lines(pdf_bytes: bytes, laparams: LAParams) -> list[str]:
    text = extract_text(io.BytesIO(pdf_bytes), laparams=laparams)
    return sorted(line for line in text.splitlines() if line.strip())


VECTOR_PAGE = _segments(300) + "\n" + _labels(300)


def test_no_cap_retains_all_objects() -> None:
    (tree,) = analyze_pages(make_pdf([VECTOR_PAGE]), LAParams())
    assert count_types(tree)["LTLine"] == 300


def test_cap_above_population_is_identical() -> None:
    pdf = make_pdf([VECTOR_PAGE])
    (base,) = analyze_pages(pdf, LAParams())
    (capped,) = analyze_pages(pdf, LAParams(max_layout_objects=10_000))
    assert count_types(capped) == count_types(base)
    assert sorted_lines(pdf, LAParams(max_layout_objects=10_000)) == sorted_lines(
        pdf, LAParams()
    )


def test_cap_bounds_objects_and_keeps_text() -> None:
    pdf = make_pdf([VECTOR_PAGE])
    (tree,) = analyze_pages(pdf, LAParams(max_layout_objects=25))
    assert non_text_count(tree) == 25
    assert sorted_lines(pdf, LAParams(max_layout_objects=25)) == sorted_lines(
        pdf, LAParams()
    )


def test_cap_zero_keeps_only_text() -> None:
    pdf = make_pdf([VECTOR_PAGE])
    (tree,) = analyze_pages(pdf, LAParams(max_layout_objects=0))
    assert non_text_count(tree) == 0
    lines = sorted_lines(pdf, LAParams(max_layout_objects=0))
    assert lines == sorted_lines(pdf, LAParams())
    assert any("L0" in line for line in lines)


def test_cap_is_per_page() -> None:
    pdf = make_pdf([VECTOR_PAGE, _segments(10) + "\n" + _labels(300, step=300)])
    first, second = analyze_pages(pdf, LAParams(max_layout_objects=25))
    assert non_text_count(first) == 25
    assert non_text_count(second) == 10


def test_objects_inside_figures_count_toward_cap() -> None:
    pdf = make_pdf_with_form(100)
    (tree,) = analyze_pages(pdf, LAParams(max_layout_objects=10))
    counts = count_types(tree)
    assert counts["LTFigure"] == 1
    assert non_text_count(tree) == 10
    assert "Hello form" in extract_text(
        io.BytesIO(pdf), laparams=LAParams(max_layout_objects=10)
    )


def test_cap_hit_logs_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    pdf = make_pdf([VECTOR_PAGE])
    with caplog.at_level("WARNING", logger="pdfminer.converter"):
        analyze_pages(pdf, LAParams(max_layout_objects=5))
    warnings = [r for r in caplog.records if "max_layout_objects" in r.message]
    assert len(warnings) == 1


def test_invalid_values_rejected() -> None:
    with pytest.raises(PDFValueError):
        LAParams(max_layout_objects=-1)
    with pytest.raises(PDFTypeError):
        LAParams(max_layout_objects=1.5)  # type: ignore[arg-type]
    with pytest.raises(PDFTypeError):
        LAParams(max_layout_objects="10")  # type: ignore[arg-type]
