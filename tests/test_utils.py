from nose.tools import assert_equal, assert_raises
import pathlib

from pdfminer.layout import LTComponent
from pdfminer.utils import open_filename, Plane, shorten_str

from .helpers import absolute_sample_path


class TestOpenFilename:
    def test_string_input(self):
        filename = absolute_sample_path("simple1.pdf")
        opened = open_filename(filename)
        assert_equal(opened.closing, True)

    def test_pathlib_input(self):
        filename = pathlib.Path(absolute_sample_path("simple1.pdf"))
        opened = open_filename(filename)
        assert_equal(opened.closing, True)

    def test_file_input(self):
        filename = absolute_sample_path("simple1.pdf")
        with open(filename, "rb") as in_file:
            opened = open_filename(in_file)
            assert_equal(opened.file_handler, in_file)

    def test_unsupported_input(self):
        assert_raises(TypeError, open_filename, 0)


class TestPlane:
    def test_find_nothing_in_empty_bbox(self):
        plane, _ = self.given_plane_with_one_object()
        result = list(plane.find((50, 50, 100, 100)))
        assert_equal(result, [])

    def test_find_nothing_after_removing(self):
        plane, obj = self.given_plane_with_one_object()
        plane.remove(obj)
        result = list(plane.find((0, 0, 100, 100)))
        assert_equal(result, [])

    def test_find_object_in_whole_plane(self):
        plane, obj = self.given_plane_with_one_object()
        result = list(plane.find((0, 0, 100, 100)))
        assert_equal(result, [obj])

    def test_find_if_object_is_smaller_than_gridsize(self):
        plane, obj = self.given_plane_with_one_object(object_size=1,
                                                      gridsize=100)
        result = list(plane.find((0, 0, 100, 100)))
        assert_equal(result, [obj])

    def test_find_object_if_much_larger_than_gridsize(self):
        plane, obj = self.given_plane_with_one_object(object_size=100,
                                                      gridsize=10)
        result = list(plane.find((0, 0, 100, 100)))
        assert_equal(result, [obj])

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
        assert_equal(s, 'Hello ... World')

    def test_shorten_short_str_is_same(self):
        s = 'Hello World'
        assert_equal(s, shorten_str(s, 50))

    def test_shorten_to_really_short(self):
        assert_equal('Hello', shorten_str('Hello World', 5))
