import math
import pathlib

import pytest

from pdfminer.layout import LTComponent
from pdfminer.utils import (
    Matrix,
    Plane,
    Point,
    Rect,
    apply_matrix_pt,
    apply_matrix_rect,
    format_int_alpha,
    format_int_roman,
    mult_matrix,
    open_filename,
    shorten_str,
    translate_matrix_inside,
)
from tests.helpers import absolute_sample_path


class TestOpenFilename:
    def test_string_input(self):
        filename = absolute_sample_path("simple1.pdf")
        opened = open_filename(filename)
        assert opened.closing

    def test_pathlib_input(self):
        filename = pathlib.Path(absolute_sample_path("simple1.pdf"))
        opened = open_filename(filename)
        assert opened.closing

    def test_file_input(self):
        filename = absolute_sample_path("simple1.pdf")
        with open(filename, "rb") as in_file:
            opened = open_filename(in_file)
            assert opened.file_handler == in_file

    def test_unsupported_input(self):
        with pytest.raises(TypeError):
            open_filename(0)


class TestPlane:
    def test_find_nothing_in_empty_bbox(self):
        plane, _ = self.given_plane_with_one_object()
        result = list(plane.find((50, 50, 100, 100)))
        assert result == []

    def test_find_nothing_after_removing(self):
        plane, obj = self.given_plane_with_one_object()
        plane.remove(obj)
        result = list(plane.find((0, 0, 100, 100)))
        assert result == []

    def test_find_object_in_whole_plane(self):
        plane, obj = self.given_plane_with_one_object()
        result = list(plane.find((0, 0, 100, 100)))
        assert result == [obj]

    def test_find_if_object_is_smaller_than_gridsize(self):
        plane, obj = self.given_plane_with_one_object(object_size=1, gridsize=100)
        result = list(plane.find((0, 0, 100, 100)))
        assert result == [obj]

    def test_find_object_if_much_larger_than_gridsize(self):
        plane, obj = self.given_plane_with_one_object(object_size=100, gridsize=10)
        result = list(plane.find((0, 0, 100, 100)))
        assert result == [obj]

    @staticmethod
    def given_plane_with_one_object(object_size=50, gridsize=50):
        bounding_box = (0, 0, 100, 100)
        plane = Plane(bounding_box, gridsize)
        obj = LTComponent((0, 0, object_size, object_size))
        plane.add(obj)
        return plane, obj


class TestFunctions:
    def test_shorten_str(self):
        s = shorten_str("Hello there World", 15)
        assert s == "Hello ... World"

    def test_shorten_short_str_is_same(self):
        s = "Hello World"
        assert shorten_str(s, 50) == s

    def test_shorten_to_really_short(self):
        assert shorten_str("Hello World", 5) == "Hello"

    def test_format_int_alpha(self):
        assert format_int_alpha(1) == "a"
        assert format_int_alpha(2) == "b"
        assert format_int_alpha(26) == "z"
        assert format_int_alpha(27) == "aa"
        assert format_int_alpha(28) == "ab"
        assert format_int_alpha(26 * 2) == "az"
        assert format_int_alpha(26 * 2 + 1) == "ba"
        assert format_int_alpha(26 * 27) == "zz"
        assert format_int_alpha(26 * 27 + 1) == "aaa"

    def test_format_int_roman(self):
        assert format_int_roman(1) == "i"
        assert format_int_roman(2) == "ii"
        assert format_int_roman(3) == "iii"
        assert format_int_roman(4) == "iv"
        assert format_int_roman(5) == "v"
        assert format_int_roman(6) == "vi"
        assert format_int_roman(7) == "vii"
        assert format_int_roman(8) == "viii"
        assert format_int_roman(9) == "ix"
        assert format_int_roman(10) == "x"
        assert format_int_roman(11) == "xi"
        assert format_int_roman(20) == "xx"
        assert format_int_roman(40) == "xl"
        assert format_int_roman(45) == "xlv"
        assert format_int_roman(50) == "l"
        assert format_int_roman(90) == "xc"
        assert format_int_roman(91) == "xci"
        assert format_int_roman(100) == "c"


@pytest.mark.parametrize(
    ("m0", "m1", "expected"),
    [
        ((1, 0, 0, 1, 0, 0), (1, 0, 0, 1, 0, 0), (1, 0, 0, 1, 0, 0)),
        ((1, 2, 3, 2, -4, 1), (1, 0, 0, 1, 0, 0), (1, 2, 3, 2, -4, 1)),
        ((1, 2, 3, 2, -4, 1), (3, 4, 1, 2, -2, 1), (5, 8, 11, 16, -13, -13)),
        ((1, -1, 1, -1, 1, -1), (1, 1, 1, 1, 1, 1), (0, 0, 0, 0, 1, 1)),
    ],
)
def test_mult_matrix(m0: Matrix, m1: Matrix, expected: Matrix) -> None:
    assert mult_matrix(m0, m1) == expected


@pytest.mark.parametrize(
    ("m0", "p0", "expected"),
    [
        ((1, 2, 3, 2, -4, 1), (0, 0), (1, 2, 3, 2, -4, 1)),
        ((1, 0, 0, 1, 0, 0), (12, -32), (1, 0, 0, 1, 12, -32)),
        ((1, 0, 0, 1, 3, -3), (12, -32), (1, 0, 0, 1, 15, -35)),
        ((2, 0, 0, 2, 0, 0), (1, -1), (2, 0, 0, 2, 2, -2)),
        ((0, 1, -1, 0, 0, 0), (1, 0), (0, 1, -1, 0, 0, 1)),
        ((0, 1, -1, 0, 0, 0), (0, 1), (0, 1, -1, 0, -1, 0)),
    ],
)
def test_translate_matrix(m0: Matrix, p0: Point, expected: Matrix) -> None:
    assert translate_matrix_inside(m0, p0) == expected


@pytest.mark.parametrize(
    ("m0", "p0", "expected"),
    [
        ((1, 0, 0, 1, 0, 0), (0, 0), (0, 0)),
        ((1, 0, 0, 1, 0, 0), (33, 21), (33, 21)),
        ((1, 2, 3, 2, -4, 1), (0, 0), (-4, 1)),
    ],
)
def test_apply_matrix_pt(m0: Matrix, p0: Point, expected: Point) -> None:
    assert apply_matrix_pt(m0, p0) == expected


@pytest.mark.parametrize(
    ("m0", "r0", "expected"),
    [
        # Identity
        ((1, 0, 0, 1, 0, 0), (0, 0, 100, 200), (0, 0, 100, 200)),
        # Identity
        ((1, 0, 0, 1, 0, 0), (20, 30, 40, 50), (20, 30, 40, 50)),
        # Translate x
        ((1, 0, 0, 1, 5, 0), (0, 1, 2, 3), (5, 1, 7, 3)),
        # Translate y
        ((1, 0, 0, 1, 0, 7), (0, 2, 4, 6), (0, 9, 4, 13)),
        # Scale x
        ((2, 0, 0, 1, 0, 0), (0, 1, 2, 3), (0, 1, 4, 3)),
        # Scale y
        ((1, 0, 0, 2, 0, 0), (0, 1, 2, 3), (0, 2, 2, 6)),
        # Rotate 90 degrees
        ((0, 1, 1, 0, 0, 0), (3, 4, 7, 6), (4, 3, 6, 7)),
        # Rotate 180 degrees, and swap min and max
        ((-1, 0, 0, -1, 0, 0), (3, 4, 7, 6), (-7, -6, -3, -4)),
        # Rotate 270 degrees, and swap min and max y-axis
        ((0, -1, 1, 0, 0, 0), (3, 4, 7, 6), (4, -7, 6, -3)),
        # Rotate 10 degrees
        # (3, 4) -> (2.25983055,4.46017555)
        # (7, 4) -> (6.19906156,5.15476826)
        # (7, 6) -> (5.85176521,7.12438376)
        # (3, 6) -> (1.91253419,6.42979105)
        # Fitting outside:
        # (1.91, 4.46, 6.19, 7.12)
        (
            (
                math.cos(math.radians(10)),
                math.sin(math.radians(10)),
                -math.sin(math.radians(10)),
                math.cos(math.radians(10)),
                0,
                0,
            ),
            (3, 4, 7, 6),  # (3, 4) -> (7, 4) -> (7, 6), (3, 6)
            (
                pytest.approx(1.91253419),
                pytest.approx(4.46017555),
                pytest.approx(6.19906156),
                pytest.approx(7.12438376),
            ),
        ),
        # Skew x-axis by 5 degrees counter clockwise, and y-axis by 7 degrees clockwise
        # x0 = x0 + tan(7°) * y0 = 3 + 0.12 * 4 = 3.49
        # y0 = tan(5°) * x0 + y0 = 0.08 * 3 + 4 = 4.26
        # x1 = x1 + tan(7°) * y1 = 7 + 0.12 * 6 = 7.74
        # y1 = tan(5°) * x1 + y1 = 0.08 * 7 + 6 = 6.61
        (
            (1, math.tan(math.radians(5)), math.tan(math.radians(7)), 1, 0, 0),
            (3, 4, 7, 6),
            (
                pytest.approx(3.4911382436116183),
                pytest.approx(4.262465990577772),
                pytest.approx(7.736707365417428),
                pytest.approx(6.612420644681468),
            ),
        ),
        # Skew x-axis by 11 degrees clockwise, and y-axis by 9 degrees counter clockwise
        # The left side is determined by the projection of the left-top (lt) corner. The
        # right side by the right-bottom (rb) corner. The bottom by the right-bottom.
        # And the top by the left-top.
        # x0 = lt_x + tan(-9°) * lt_y = 2.05
        # y0 = tan(-11°) * rb_x + rb_y = 2.64
        # x1 = rb_x + tan(-9°) * rb_y = 6.37
        # y1 = tan(-11°) * lt_x + lt_y = 5.42
        (
            (1, math.tan(math.radians(-11)), math.tan(math.radians(-9)), 1, 0, 0),
            (3, 4, 7, 6),
            (
                pytest.approx(2.0496933580527825),
                pytest.approx(2.6393378360359705),
                pytest.approx(6.366462238701855),
                pytest.approx(5.416859072586845),
            ),
        ),
    ],
)
def test_apply_matrix_rect_outside(m0: Matrix, r0: Rect, expected: Rect) -> None:
    """Test rotation examples based on PDF reference 4.2.2 Common Transformations"""
    assert apply_matrix_rect(m0, r0) == expected
