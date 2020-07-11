from nose.tools import assert_equal

from pdfminer.converter import PDFLayoutAnalyzer
from pdfminer.layout import LTContainer
from pdfminer.pdfinterp import PDFGraphicState


class TestPaintPath():
    def test_paint_path(self):
        path = [('m', 6, 73), ('l', 7, 73)]
        analyzer = self._get_analyzer()
        analyzer.cur_item = LTContainer([0, 100, 0, 100])
        analyzer.paint_path(PDFGraphicState(), False, False, False, path)
        assert_equal(len(analyzer.cur_item._objs), 1)

    def test_paint_path_mlllh(self):
        path = [('m', 6, 73), ('l', 7, 73), ('l', 7, 91),  ('l', 6, 91), ('h',)]
        analyzer = self._get_analyzer()
        analyzer.cur_item = LTContainer([0, 100, 0, 100])
        analyzer.paint_path(PDFGraphicState(), False, False, False, path)
        assert_equal(len(analyzer.cur_item), 1)

    def test_paint_path_multiple_mlllh(self):
        """Path from samples/contrib/issue-00369-excel.pdf"""
        path = [
            ('m', 6, 73), ('l', 7, 73), ('l', 7, 91), ('l', 6, 91), ('h',),
            ('m', 4, 73), ('l', 6, 73), ('l', 6, 91), ('l', 4, 91), ('h',),
            ('m', 67, 2), ('l', 68, 2), ('l', 68, 3), ('l', 67, 3), ('h',)
        ]
        analyzer = self._get_analyzer()
        analyzer.cur_item = LTContainer([0, 100, 0, 100])
        analyzer.paint_path(PDFGraphicState(), False, False, False, path)
        assert_equal(len(analyzer.cur_item._objs), 3)

    def _get_analyzer(self):
        analyzer = PDFLayoutAnalyzer(None)
        analyzer.set_ctm([1, 0, 0, 1, 0, 0])
        return analyzer
