from typing import Any, Dict, Union

import pytest

from pdfminer.converter import PDFPageAggregator
from pdfminer.layout import LAParams
from pdfminer.pdffont import PDFCIDFont, PDFFont, get_widths
from pdfminer.pdfinterp import PDFPageInterpreter, PDFResourceManager
from pdfminer.pdftypes import PDFObjRef
from pdfminer.psparser import PSLiteral
from tests.helpers import absolute_sample_path


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
) -> None:
    pdffont = MockPdfFont(descriptor=dict(), widths=widths, default_width=100.0)

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
    from typing import Generator

    from pdfminer.pdfpage import PDFPage

    def pdf_to_pages(file_name: str) -> Generator[PDFPage, None, None]:
        from pdfminer.pdfpage import PDFPage

        with open(file_name, "rb") as fp:
            pages = PDFPage.get_pages(fp)
            for page in pages:
                yield page

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
