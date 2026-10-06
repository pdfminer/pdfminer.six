import pytest

from pdfminer.converter import PDFLayoutAnalyzer
from pdfminer.layout import LTContainer
from pdfminer.pdfinterp import PDFPageInterpreter, PDFResourceManager
from pdfminer.pdftypes import PDFStream
from pdfminer.psparser import LIT


@pytest.mark.parametrize("vertical", [False, True])
@pytest.mark.parametrize("charspace", [2, -2, 0])
@pytest.mark.parametrize(
    "operators, offsets",
    [
        (b"<0041> Tj <0042> Tj", (0, 0, 0)),
        (b"[<0041>] TJ [<0042>] TJ", (0, 0, 0)),
        (b"[<00410042>] TJ", (0, 0, 0)),
        (b"[100 <0041> 200 <0042> 300] TJ", (-1, -3, -6)),
        (b"[<0041> 100] TJ <0042> Tj", (0, -1, -1)),
        (b"<> Tj <0041> Tj [] TJ <> Tj <0042> Tj", (0, 0, 0)),
    ],
)
def test_character_spacing_displacement(vertical, charspace, operators, offsets):
    """Character spacing is part of every glyph's displacement (issue #1128)."""
    manager = PDFResourceManager()
    device = PDFLayoutAnalyzer(manager)
    device.cur_item = LTContainer((0, 0, 200, 200))
    interpreter = PDFPageInterpreter(manager, device)
    resources = {
        "Font": {
            "F1": {
                "Subtype": LIT("Type0"),
                "BaseFont": LIT("TestFont"),
                "Encoding": LIT("Identity-V" if vertical else "Identity-H"),
                "ToUnicode": LIT("Identity-H"),
                "DescendantFonts": [
                    {
                        "Subtype": LIT("CIDFontType2"),
                        "BaseFont": LIT("TestFont"),
                        "CIDSystemInfo": {
                            "Registry": b"Adobe",
                            "Ordering": b"Identity",
                            "Supplement": 0,
                        },
                        "FontDescriptor": {"FontBBox": [0, -200, 1000, 900]},
                        "DW": 600,
                        "DW2": [880, -600],
                    }
                ],
            }
        }
    }
    content = f"BT /F1 10 Tf {charspace} Tc ".encode() + operators + b" ET"
    stream = PDFStream({}, content)
    stream.set_objid(1, 0)
    interpreter.render_contents(resources, [stream])

    axis = int(vertical)
    step = (-6 if vertical else 6) + charspace
    assert [char.get_text() for char in device.cur_item] == ["A", "B"]
    assert [char.matrix[4 + axis] for char in device.cur_item] == pytest.approx(
        [offsets[0], step + offsets[1]]
    )
    assert interpreter.textstate.linematrix[axis] == pytest.approx(
        2 * step + offsets[2]
    )
