import zlib
from io import BytesIO
from struct import pack
from unittest.mock import Mock

import pytest

from pdfminer.image import ImageWriter
from pdfminer.jbig2 import FILE_HEADER_ID, JBIG2StreamReader
from pdfminer.layout import LTImage
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdftypes import PDFObjRef, PDFStream
from pdfminer.psparser import LIT


def _indirect_null() -> PDFObjRef:
    document = Mock(spec=PDFDocument)
    document.getobj.return_value = None
    return PDFObjRef(document, 3)


@pytest.mark.parametrize(
    "filter_attrs",
    [
        {},
        {"DecodeParms": None},
        {
            "Filter": [LIT("FlateDecode"), LIT("JBIG2Decode")],
            "DecodeParms": [None, None],
        },
        {"DecodeParms": {"JBIG2Globals": _indirect_null()}},
    ],
    ids=[
        "absent-params",
        "null-params",
        "multiple-filters-null-params",
        "indirect-null",
    ],
)
def test_export_jbig2_without_globals(tmp_path, filter_attrs):
    # A blank 8-by-4 page: width, height, resolution, flags and striping info.
    page_info = pack(">IIIIBH", 8, 4, 0, 0, 0, 0)
    # Page-information segment 0, no references, associated with page 1.
    data = pack(">IBBBI", 0, 48, 0, 1, len(page_info)) + page_info
    attrs = {
        "Width": 8,
        "Height": 4,
        "BitsPerComponent": 1,
        "ColorSpace": LIT("DeviceGray"),
        "Filter": LIT("JBIG2Decode"),
        **filter_attrs,
    }
    if isinstance(attrs["Filter"], list):
        data = zlib.compress(data)
    image = LTImage("blank", PDFStream(attrs, data), (0, 0, 8, 4))

    name = ImageWriter(str(tmp_path)).export_image(image)

    exported = BytesIO((tmp_path / name).read_bytes())
    assert exported.read(13) == FILE_HEADER_ID + pack(">BI", 1, 1)
    segments = JBIG2StreamReader(exported).get_segments()
    assert [segment["flags"]["type"] for segment in segments] == [48, 49, 51]
    assert segments[0]["page_assoc"] == 1
    assert segments[0]["raw_data"] == page_info
