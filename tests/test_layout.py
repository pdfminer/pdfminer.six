import unittest

from pdfminer.layout import (
    LTLayoutContainer,
    LAParams, LTLine,
    LTTextLineHorizontal,
    LTTextLineVertical,
)
from pdfminer.utils import Plane


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

    def test_curve_between_textlines(self):
        """
        LTTextLines should not be grouped into a single LTTextBox when there is
        an LTCurve between.
        """

        def any_in_overlap(plane, obj1, obj2):
            """Check if there are any objects in the overlap between obj1 and
            obj2.

            This augments the bounding boxes of the LTTextLines with
            line_margin, as in find_neighbors.
            """
            bbox1 = obj1.get_bbox_plus_tolerance(
                laparams.line_margin * obj1.height)
            bbox2 = obj2.get_bbox_plus_tolerance(
                laparams.line_margin * obj2.height)
            x0 = max(bbox1[0], bbox2[0])
            y0 = max(bbox1[1], bbox2[1])
            x1 = min(bbox1[2], bbox2[2])
            y1 = min(bbox1[3], bbox2[3])
            objs = set(plane.find((x0, y0, x1, y1)))
            return not bool(objs.difference((obj1, obj2)))

        laparams = LAParams(lines_merge=any_in_overlap)
        layout = LTLayoutContainer((0, 0, 50, 50))
        separator_curve = LTLine(1, (0, 5), (50, 5))
        layout.add(separator_curve)
        line1 = LTTextLineHorizontal(laparams.word_margin)
        line1.set_bbox((0, 0, 50, 5))
        line2 = LTTextLineHorizontal(laparams.word_margin)
        line2.set_bbox((0, 5, 50, 10))
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
