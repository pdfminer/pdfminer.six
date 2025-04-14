import pathlib

import pytest

from pdfminer.layout import LTComponent
from pdfminer.utils import (
    Plane,
    format_int_alpha,
    format_int_roman,
    open_filename,
    shorten_str, apply_matrix_rect, mult_matrix, translate_matrix_inside, apply_matrix_pt,
    Matrix, Point,
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
        ((1, -1, 1, -1, 1, -1), (1, 1, 1, 1, 1, 1), (0, 0, 0, 0, 1, 1))
    ]
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
    ]
)
def test_translate_matrix(m0: Matrix, p0: Point, expected: Matrix) -> None:
    assert translate_matrix_inside(m0, p0) == expected


@pytest.mark.parametrize(
    ("m0", "p0", "expected"),
    [
        ((1, 0, 0, 1, 0, 0), (0, 0), (0, 0)),
        ((1, 0, 0, 1, 0, 0), (33, 21), (33, 21)),
        ((1, 2, 3, 2, -4, 1), (0, 0), (-4, 1)),
    ]
)
def test_apply_matrix_pt(m0: Matrix, p0: Point, expected: Point) -> None:
    assert apply_matrix_pt(m0, p0) == expected

