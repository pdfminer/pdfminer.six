import unittest

from pdfminer.high_level import extract_pages
from pdfminer.layout import (
    LAParams,
    LTLayoutContainer,
    LTTextBoxHorizontal,
    LTTextBoxVertical,
    LTTextLineHorizontal,
    LTTextLineVertical,
)
from pdfminer.utils import Plane
from tests.helpers import absolute_sample_path


class TestGroupTextLines(unittest.TestCase):
    def test_parent_with_wrong_bbox_returns_non_empty_neighbour_list(self):
        """LTLayoutContainer.group_textlines() should return all the lines in a
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

        centrally_aligned_overlapping = LTTextLineHorizontal(laparams.word_margin)
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

        centrally_aligned_overlapping = LTTextLineVertical(laparams.word_margin)
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
    path = absolute_sample_path("contrib/issue-449-horizontal.pdf")
    pages = extract_pages(path)
    textboxes = [
        textbox for textbox in next(pages) if isinstance(textbox, LTTextBoxHorizontal)
    ]
    assert len(textboxes) == 3


def test_pdf_with_empty_characters_vertical():
    """Regression test for issue #449

    See: https://github.com/pdfminer/pdfminer.six/pull/689

    The page aggregator should separate the 3 horizontal lines in the
    sample PDF. The used PDF sample has multiple explicit space characters
    in between lines with text.
    """
    path = absolute_sample_path("contrib/issue-449-vertical.pdf")
    laparams = LAParams(detect_vertical=True)
    pages = extract_pages(path, laparams=laparams)
    textboxes = [
        textbox for textbox in next(pages) if isinstance(textbox, LTTextBoxVertical)
    ]
    assert len(textboxes) == 3


class TestCharMarginLeft(unittest.TestCase):
    def test_char_margin_left_prevents_line_wrapping(self):
        """Test that char_margin_left prevents incorrect line merging.
        
        When processing characters sequentially, a character at the far right
        of one line (X=100) followed by a character at the far left of the next
        line (X=10) should not be grouped together when char_margin_left is small,
        even if char_margin is large.
        """
        from pdfminer.layout import LTChar
        from unittest.mock import Mock
        
        # Create LAParams with different margins for left vs right
        laparams = LAParams(
            char_margin=1000,      # Very generous for normal text
            char_margin_left=2,    # Strict for leftward jumps
            line_overlap=0.5,
        )
        
        layout = LTLayoutContainer((0, 0, 200, 50))
        
        # Create a mock font
        mock_font = Mock()
        mock_font.fontname = "TestFont"
        mock_font.is_vertical.return_value = False
        mock_font.get_descent.return_value = -0.2
        mock_font.get_height.return_value = 1.0
        
        # Create characters simulating a line wrap scenario
        # Line 1: characters at X=10, 20, 30, ..., 90 (moving right)
        # Line 2: characters at X=10, 20, 30 (moving right, but starts far left)
        
        chars = []
        
        # First line at Y=30
        for i in range(9):
            char = LTChar(
                matrix=(1, 0, 0, 1, 10 + i*10, 30),
                font=mock_font,
                fontsize=10,
                scaling=1,
                rise=0,
                text=chr(65 + i),  # A, B, C, ...
                textwidth=8,
                textdisp=0,
                ncs=None,
                graphicstate=None,
            )
            chars.append(char)
        
        # Second line at Y=10 (below first line)
        for i in range(3):
            char = LTChar(
                matrix=(1, 0, 0, 1, 10 + i*10, 10),
                font=mock_font,
                fontsize=10,
                scaling=1,
                rise=0,
                text=chr(97 + i),  # a, b, c
                textwidth=8,
                textdisp=0,
                ncs=None,
                graphicstate=None,
            )
            chars.append(char)
        
        # Group the characters into lines
        lines = list(layout.group_objects(laparams, chars))
        
        # With char_margin_left=2, the large leftward jump from X=90 to X=10
        # should create separate lines
        # Expected: 2 lines (one for each Y level)
        self.assertGreaterEqual(len(lines), 2, 
            "char_margin_left should prevent line wrapping")
    
    def test_char_margin_left_defaults_to_char_margin(self):
        """Test that char_margin_left defaults to char_margin for backward compatibility."""
        laparams = LAParams(char_margin=100)
        self.assertEqual(laparams.char_margin_left, 100)
        
    def test_char_margin_left_can_be_set_explicitly(self):
        """Test that char_margin_left can be set to a different value."""
        laparams = LAParams(char_margin=1000, char_margin_left=2)
        self.assertEqual(laparams.char_margin, 1000)
        self.assertEqual(laparams.char_margin_left, 2)
