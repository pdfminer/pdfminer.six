import pathlib

import pytest

from helpers import absolute_sample_path
from pdfminer.layout import LTComponent
from pdfminer.utils import open_filename, Plane, shorten_str, \
    format_int_roman, format_int_alpha


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
        plane, obj = self.given_plane_with_one_object(object_size=1,
                                                      gridsize=100)
        result = list(plane.find((0, 0, 100, 100)))
        assert result == [obj]

    def test_find_object_if_much_larger_than_gridsize(self):
        plane, obj = self.given_plane_with_one_object(object_size=100,
                                                      gridsize=10)
        result = list(plane.find((0, 0, 100, 100)))
        assert result == [obj]

    @staticmethod
    def given_plane_with_one_object(object_size=50, gridsize=50):
        bounding_box = (0, 0, 100, 100)
        plane = Plane(bounding_box, gridsize)
        obj = LTComponent((0, 0, object_size, object_size))
        plane.add(obj)
        return plane, obj


class TestFunctions(object):
    def test_shorten_str(self):
        s = shorten_str('Hello there World', 15)
        assert s == 'Hello ... World'

    def test_shorten_short_str_is_same(self):
        s = 'Hello World'
        assert shorten_str(s, 50) == s

    def test_shorten_to_really_short(self):
        assert shorten_str('Hello World', 5) == 'Hello'

    def test_format_int_alpha(self):
        assert format_int_alpha(1) == 'a'
        assert format_int_alpha(2) == 'b'
        assert format_int_alpha(26) == 'z'
        assert format_int_alpha(27) == 'aa'
        assert format_int_alpha(28) == 'ab'
        assert format_int_alpha(26 * 2) == 'az'
        assert format_int_alpha(26 * 2 + 1) == 'ba'
        assert format_int_alpha(26 * 27) == 'zz'
        assert format_int_alpha(26 * 27 + 1) == 'aaa'

    def test_format_int_roman(self):
        assert format_int_roman(1) == 'i'
        assert format_int_roman(2) == 'ii'
        assert format_int_roman(3) == 'iii'
        assert format_int_roman(4) == 'iv'
        assert format_int_roman(5) == 'v'
        assert format_int_roman(6) == 'vi'
        assert format_int_roman(7) == 'vii'
        assert format_int_roman(8) == 'viii'
        assert format_int_roman(9) == 'ix'
        assert format_int_roman(10) == 'x'
        assert format_int_roman(11) == 'xi'
        assert format_int_roman(20) == 'xx'
        assert format_int_roman(40) == 'xl'
        assert format_int_roman(45) == 'xlv'
        assert format_int_roman(50) == 'l'
        assert format_int_roman(90) == 'xc'
        assert format_int_roman(91) == 'xci'
        assert format_int_roman(100) == 'c'
