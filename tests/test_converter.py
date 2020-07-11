from nose.tools import assert_equal

from pdfminer.converter import PDFLayoutAnalyzer
from pdfminer.layout import LTContainer
from pdfminer.pdfinterp import PDFGraphicState


class TestPaintPath():
    def test_paint_path(self):
        path = [('m', 136, 73.28), ('l', 137.28, 73.28)]
        analyzer = self._get_analyzer()
        analyzer.cur_item = LTContainer([0, 100, 0, 100])
        analyzer.paint_path(PDFGraphicState(), False, False, False, path)
        assert_equal(len(analyzer.cur_item._objs), 1)

    def test_paint_path_mlllh(self):
        path = [('m', 136, 73.28), ('l', 137.28, 73.28), ('l', 137.28, 91.04), ('l', 136, 91.04), ('h',)]
        analyzer = self._get_analyzer()
        analyzer.cur_item = LTContainer([0, 100, 0, 100])
        analyzer.paint_path(PDFGraphicState(), False, False, False, path)
        assert_equal(len(analyzer.cur_item), 1)

    def test_paint_path_multiple_mlllh(self):
        """Path from samples/contrib/issue-00369-excel.pdf"""
        path = [
            ('m', 136, 73.28), ('l', 137.28, 73.28), ('l', 137.28, 91.04), ('l', 136, 91.04), ('h',),
            ('m', 204.8, 73.28), ('l', 206.08, 73.28), ('l', 206.08, 91.04), ('l', 204.8, 91.04), ('h',),
            ('m', 67.2, 72), ('l', 68.48, 72), ('l', 68.48, 133.28), ('l', 67.2, 133.28), ('h',)
        ]
        analyzer = self._get_analyzer()
        analyzer.cur_item = LTContainer([0, 100, 0, 100])
        analyzer.paint_path(PDFGraphicState(), False, False, False, path)
        assert_equal(len(analyzer.cur_item._objs), 3)

    def _get_analyzer(self):
        analyzer = PDFLayoutAnalyzer(None)
        analyzer.set_ctm([1, 0, 0, 1, 0, 0])
        return analyzer
