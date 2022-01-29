import io
from tempfile import TemporaryFile

from pdfminer.converter import PDFLayoutAnalyzer, PDFConverter
from pdfminer.high_level import extract_pages
from pdfminer.layout import LTContainer, LTRect, LTLine, LTCurve
from pdfminer.pdfinterp import PDFGraphicState


class TestPaintPath:
    def test_paint_path(self):
        path = [('m', 6, 7), ('l', 7, 7)]
        analyzer = self._get_analyzer()
        analyzer.cur_item = LTContainer([0, 100, 0, 100])
        analyzer.paint_path(PDFGraphicState(), False, False, False, path)
        assert len(analyzer.cur_item._objs) == 1

    def test_paint_path_mlllh(self):
        path = [('m', 6, 7), ('l', 7, 7), ('l', 7, 91), ('l', 6, 91), ('h',)]
        analyzer = self._get_analyzer()
        analyzer.cur_item = LTContainer([0, 100, 0, 100])
        analyzer.paint_path(PDFGraphicState(), False, False, False, path)
        assert len(analyzer.cur_item) == 1

    def test_paint_path_multiple_mlllh(self):
        """Path from samples/contrib/issue-00369-excel.pdf"""
        path = [
            ('m', 6, 7), ('l', 7, 7), ('l', 7, 91), ('l', 6, 91), ('h',),
            ('m', 4, 7), ('l', 6, 7), ('l', 6, 91), ('l', 4, 91), ('h',),
            ('m', 67, 2), ('l', 68, 2), ('l', 68, 3), ('l', 67, 3), ('h',)
        ]
        analyzer = self._get_analyzer()
        analyzer.cur_item = LTContainer([0, 100, 0, 100])
        analyzer.paint_path(PDFGraphicState(), False, False, False, path)
        assert len(analyzer.cur_item._objs) == 3

    def test_paint_path_quadrilaterals(self):
        """via https://github.com/pdfminer/pdfminer.six/issues/473"""

        def parse(path):
            analyzer = self._get_analyzer()
            analyzer.cur_item = LTContainer([0, 1000, 0, 1000])
            analyzer.paint_path(PDFGraphicState(), False, False, False, path)
            return analyzer.cur_item._objs

        def get_types(path):
            return list(map(type, parse(path)))

        # Standard rect
        assert get_types(
            [
                ("m", 10, 90),
                ("l", 90, 90),
                ("l", 90, 10),
                ("l", 10, 10),
                ("h",),
            ]
        ) == [LTRect]

        # Same but mllll variation
        assert get_types(
            [
                ("m", 10, 90),
                ("l", 90, 90),
                ("l", 90, 10),
                ("l", 10, 10),
                ("l", 10, 90),
            ]
        ) == [LTRect]

        # Bowtie shape
        assert get_types(
            [
                ("m", 110, 90),
                ("l", 190, 10),
                ("l", 190, 90),
                ("l", 110, 10),
                ("h",),
            ]
        ) == [LTCurve]

        # Quadrilateral with one slanted side
        assert get_types(
            [
                ("m", 210, 90),
                ("l", 290, 60),
                ("l", 290, 10),
                ("l", 210, 10),
                ("h",),
            ]
        ) == [LTCurve]

        # Path with two rect subpaths
        assert get_types(
            [
                ("m", 310, 90),
                ("l", 350, 90),
                ("l", 350, 10),
                ("l", 310, 10),
                ("h",),
                ("m", 350, 90),
                ("l", 390, 90),
                ("l", 390, 10),
                ("l", 350, 10),
                ("h",),
            ]
        ) == [LTRect, LTRect]

        # Path with one rect subpath and one pentagon
        assert get_types(
            [
                ("m", 410, 90),
                ("l", 445, 90),
                ("l", 445, 10),
                ("l", 410, 10),
                ("h",),
                ("m", 455, 70),
                ("l", 475, 90),
                ("l", 490, 70),
                ("l", 490, 10),
                ("l", 455, 10),
                ("h",),
            ]
        ) == [LTRect, LTCurve]

        # Three types of simple lines
        assert get_types(
            [
                # Vertical line
                ("m", 10, 30),
                ("l", 10, 40),
                ("h",),
                # Horizontal line
                ("m", 10, 50),
                ("l", 70, 50),
                ("h",),
                # Diagonal line
                ("m", 10, 10),
                ("l", 30, 30),
                ("h",),
            ]
        ) == [LTLine, LTLine, LTLine]

        # Same as above, but 'ml' variation
        assert get_types(
            [
                # Vertical line
                ("m", 10, 30),
                ("l", 10, 40),
                # Horizontal line
                ("m", 10, 50),
                ("l", 70, 50),
                # Diagonal line
                ("m", 10, 10),
                ("l", 30, 30),
            ]
        ) == [LTLine, LTLine, LTLine]

        # There are six lines in this one-page PDF;
        # they all have shape 'ml' not 'mlh'
        ml_pdf = extract_pages("samples/contrib/pr-00530-ml-lines.pdf")
        ml_pdf_page = list(ml_pdf)[0]
        assert sum(type(item) == LTLine for item in ml_pdf_page) == 6

    def _get_analyzer(self):
        analyzer = PDFLayoutAnalyzer(None)
        analyzer.set_ctm([1, 0, 0, 1, 0, 0])
        return analyzer

    def test_paint_path_beziers(self):
        """See section 4.4, table 4.9 of the PDF reference manual"""

        def parse(path):
            analyzer = self._get_analyzer()
            analyzer.cur_item = LTContainer([0, 1000, 0, 1000])
            analyzer.paint_path(PDFGraphicState(), False, False, False, path)
            return analyzer.cur_item._objs

        # "c" operator
        assert parse([
            ("m", 72.41, 433.89),
            ("c", 72.41, 434.45, 71.96, 434.89, 71.41, 434.89),
        ])[0].pts == [
            (72.41, 433.89),
            (71.41, 434.89),
        ]

        # "v" operator
        assert parse([
            ("m", 72.41, 433.89),
            ("v", 71.96, 434.89, 71.41, 434.89),
        ])[0].pts == [
            (72.41, 433.89),
            (71.41, 434.89),
        ]

        # "y" operator
        assert parse([
            ("m", 72.41, 433.89),
            ("y", 72.41, 434.45, 71.41, 434.89),
        ])[0].pts == [
            (72.41, 433.89),
            (71.41, 434.89),
        ]


class TestBinaryDetector():
    def test_stringio(self):
        assert not PDFConverter._is_binary_stream(io.StringIO())

    def test_bytesio(self):
        assert PDFConverter._is_binary_stream(io.BytesIO())

    def test_tmpfile(self):
        with TemporaryFile(mode='w') as f:
            assert not PDFConverter._is_binary_stream(f)

    def test_binary_tmpfile(self):
        with TemporaryFile(mode='wb') as f:
            assert PDFConverter._is_binary_stream(f)

    def test_non_file_like_object_defaults_to_binary(self):
        assert PDFConverter._is_binary_stream(object())

    def test_textiowrapper(self):
        assert not PDFConverter._is_binary_stream(io.TextIOBase())
