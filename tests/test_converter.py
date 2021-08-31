import io
from tempfile import TemporaryFile

from nose.tools import assert_equal, assert_false, assert_true

from pdfminer.converter import PDFLayoutAnalyzer, PDFConverter
from pdfminer.layout import LTContainer, LTRect, LTCurve
from pdfminer.pdfinterp import PDFGraphicState


class TestPaintPath():
    def test_paint_path(self):
        path = [('m', 6, 7), ('l', 7, 7)]
        analyzer = self._get_analyzer()
        analyzer.cur_item = LTContainer([0, 100, 0, 100])
        analyzer.paint_path(PDFGraphicState(), False, False, False, path)
        assert_equal(len(analyzer.cur_item._objs), 1)

    def test_paint_path_mlllh(self):
        path = [('m', 6, 7), ('l', 7, 7), ('l', 7, 91),  ('l', 6, 91), ('h',)]
        analyzer = self._get_analyzer()
        analyzer.cur_item = LTContainer([0, 100, 0, 100])
        analyzer.paint_path(PDFGraphicState(), False, False, False, path)
        assert_equal(len(analyzer.cur_item), 1)

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
        assert_equal(len(analyzer.cur_item._objs), 3)

    def test_paint_path_quadrilaterals(self):
        """via https://github.com/pdfminer/pdfminer.six/issues/473"""

        def parse(path):
            analyzer = self._get_analyzer()
            analyzer.cur_item = LTContainer([0, 1000, 0, 1000])
            analyzer.paint_path(PDFGraphicState(), False, False, False, path)
            return analyzer.cur_item._objs

        def get_types(path):
            return list(map(type, parse(path)))

        assert_equal(get_types([
            ("m", 10, 90),
            ("l", 90, 90),
            ("l", 90, 10),
            ("l", 10, 10),
            ("h",),
        ]), [LTRect])

        assert_equal(get_types([
            ("m", 110, 90),
            ("l", 190, 10),
            ("l", 190, 90),
            ("l", 110, 10),
            ("h",),
        ]), [LTCurve])

        assert_equal(get_types([
            ("m", 210, 90),
            ("l", 290, 60),
            ("l", 290, 10),
            ("l", 210, 10),
            ("h",),
        ]), [LTCurve])

        assert_equal(get_types([
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
        ]), [LTRect, LTRect])

        assert_equal(get_types([
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
        ]), [LTRect, LTCurve])

    def _get_analyzer(self):
        analyzer = PDFLayoutAnalyzer(None)
        analyzer.set_ctm([1, 0, 0, 1, 0, 0])
        return analyzer


class TestBinaryDetector():
    def test_stringio(self):
        assert_false(PDFConverter._is_binary_stream(io.StringIO()))

    def test_bytesio(self):
        assert_true(PDFConverter._is_binary_stream(io.BytesIO()))

    def test_tmpfile(self):
        with TemporaryFile(mode='w') as f:
            assert_false(PDFConverter._is_binary_stream(f))

    def test_binary_tmpfile(self):
        with TemporaryFile(mode='wb') as f:
            assert_true(PDFConverter._is_binary_stream(f))

    def test_non_file_like_object_defaults_to_binary(self):
        assert_true(PDFConverter._is_binary_stream(object()))

    def test_textiowrapper(self):
        assert_false(PDFConverter._is_binary_stream(io.TextIOBase()))
