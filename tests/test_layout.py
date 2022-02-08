import unittest

from pdfminer.high_level import extract_pages
from pdfminer.layout import (
    LTLayoutContainer,
    LAParams,
    LTTextLineHorizontal,
    LTTextLineVertical, LTTextBoxHorizontal, LTTextBoxVertical,
)
from pdfminer.utils import Plane
from tests.helpers import absolute_sample_path


class TestGroupTextLines(unittest.TestCase):
    def test_parent_with_wrong_bbox_returns_non_empty_neighbour_list(self):
        """
        LTLayoutContainer.group_textlines() should return all the lines in a
        separate LTTextBoxes if they do not overlap. Even when the bounding box
        of the parent container does not contain all the lines.
        """
        laparams = LAParams()
        layout = LTLayoutContainer((0, 0, 50, 50))
        line1 = LTTextLineHorizontal(laparams.word_margin)
        line1.set_bbox((0, 0, 50, 5))
        line2 = LTTextLineHorizontal(laparams.word_margin)
        line2.set_bbox((0, 50, 50, 55))
        lines = [line1, line2]

        textboxes = list(layout.group_textlines(laparams, lines))

        self.assertEqual(len(textboxes), 2)


class TestFindNeigbors(unittest.TestCase):
    def test_find_neighbors_horizontal(self):
        laparams = LAParams()
        plane = Plane((0, 0, 50, 50))

        line = LTTextLineHorizontal(laparams.word_margin)
        line.set_bbox((10, 4, 20, 6))
        plane.add(line)

        left_aligned_above = LTTextLineHorizontal(laparams.word_margin)
        left_aligned_above.set_bbox((10, 6, 15, 8))
        plane.add(left_aligned_above)

        right_aligned_below = LTTextLineHorizontal(laparams.word_margin)
        right_aligned_below.set_bbox((15, 2, 20, 4))
        plane.add(right_aligned_below)

        centrally_aligned_overlapping = LTTextLineHorizontal(
            laparams.word_margin)
        centrally_aligned_overlapping.set_bbox((13, 5, 17, 7))
        plane.add(centrally_aligned_overlapping)

        not_aligned = LTTextLineHorizontal(laparams.word_margin)
        not_aligned.set_bbox((0, 6, 5, 8))
        plane.add(not_aligned)

        wrong_height = LTTextLineHorizontal(laparams.word_margin)
        wrong_height.set_bbox((10, 6, 15, 10))
        plane.add(wrong_height)

        neighbors = line.find_neighbors(plane, laparams.line_margin)
        self.assertCountEqual(
            neighbors,
            [
                line,
                left_aligned_above,
                right_aligned_below,
                centrally_aligned_overlapping,
            ],
        )

    def test_find_neighbors_vertical(self):
        laparams = LAParams()
        plane = Plane((0, 0, 50, 50))

        line = LTTextLineVertical(laparams.word_margin)
        line.set_bbox((4, 10, 6, 20))
        plane.add(line)

        bottom_aligned_right = LTTextLineVertical(laparams.word_margin)
        bottom_aligned_right.set_bbox((6, 10, 8, 15))
        plane.add(bottom_aligned_right)

        top_aligned_left = LTTextLineVertical(laparams.word_margin)
        top_aligned_left.set_bbox((2, 15, 4, 20))
        plane.add(top_aligned_left)

        centrally_aligned_overlapping = LTTextLineVertical(
            laparams.word_margin)
        centrally_aligned_overlapping.set_bbox((5, 13, 7, 17))
        plane.add(centrally_aligned_overlapping)

        not_aligned = LTTextLineVertical(laparams.word_margin)
        not_aligned.set_bbox((6, 0, 8, 5))
        plane.add(not_aligned)

        wrong_width = LTTextLineVertical(laparams.word_margin)
        wrong_width.set_bbox((6, 10, 10, 15))
        plane.add(wrong_width)

        neighbors = line.find_neighbors(plane, laparams.line_margin)
        self.assertCountEqual(
            neighbors,
            [
                line,
                bottom_aligned_right,
                top_aligned_left,
                centrally_aligned_overlapping,
            ],
        )


def test_pdf_with_empty_characters_horizontal():
    """Regression test for issue #449

    See: https://github.com/pdfminer/pdfminer.six/pull/689

    The page aggregator should separate the 3 horizontal lines in the
    sample PDF. The used PDF sample has multiple explicit space characters
    in between lines with text.
    """
    path = absolute_sample_path('contrib/issue-449-horizontal.pdf')
    pages = extract_pages(path)
    textboxes = [
        textbox
        for textbox in next(pages)
        if isinstance(textbox, LTTextBoxHorizontal)
    ]
    assert len(textboxes) == 3


def test_pdf_with_empty_characters_vertical():
    """Regression test for issue #449

    See: https://github.com/pdfminer/pdfminer.six/pull/689

    The page aggregator should separate the 3 horizontal lines in the
    sample PDF. The used PDF sample has multiple explicit space characters
    in between lines with text.
    """
    path = absolute_sample_path('contrib/issue-449-vertical.pdf')
    laparams = LAParams(detect_vertical=True)
    pages = extract_pages(path, laparams=laparams)
    textboxes = [
        textbox
        for textbox in next(pages)
        if isinstance(textbox, LTTextBoxVertical)
    ]
    assert len(textboxes) == 3
