from typing import Dict, Union

import pytest

from pdfminer.pdffont import PDFCIDFont, PDFFont
from pdfminer.pdfinterp import PDFResourceManager
from pdfminer.psparser import PSLiteral


def test_get_cmap_from_pickle():
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
    msg: str, widths: Dict[Union[str, int], float], expected: float
):
    pdffont = MockPdfFont(descriptor=dict(), widths=widths, default_width=100.0)

    assert pdffont.char_width(0) == expected, msg
