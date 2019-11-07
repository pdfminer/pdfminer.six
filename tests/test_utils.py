from nose.tools import assert_equal

from pdfminer.layout import LTComponent
from pdfminer.utils import Plane


class TestPlane(object):
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
        plane, obj = self.given_plane_with_one_object(object_size=1, gridsize=100)
        result = list(plane.find((0, 0, 100, 100)))
        assert_equal(result, [obj])

    def test_find_object_if_much_larger_than_gridsize(self):
        plane, obj = self.given_plane_with_one_object(object_size=100, gridsize=10)
        result = list(plane.find((0, 0, 100, 100)))
        assert_equal(result, [obj])

    @staticmethod
    def given_plane_with_one_object(object_size=50, gridsize=50):
        bounding_box = (0, 0, 100, 100)
        plane = Plane(bounding_box, gridsize)
        obj = LTComponent((0, 0, object_size, object_size))
        plane.add(obj)
        return plane, obj
