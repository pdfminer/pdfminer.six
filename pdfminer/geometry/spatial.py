"""Spatial operations — bounding boxes, distances, and spatial data structures.

Contains functions for computing bounding rectangles, measuring distances
between layout components, and the Plane spatial index used for efficient
area queries during layout analysis.
"""

import contextlib
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, Generic, TypeVar

if TYPE_CHECKING:
    from pdfminer.layout import LTComponent

from pdfminer.geometry.matrix import Point, Rect

# INF is defined in pdfminer.utils for backward compatibility; import it here
# for the get_bound function
from pdfminer.utils import INF

# ─── Bounding box computation ──────────────────────────────────────────────


def get_bound(pts: Iterable[Point]) -> Rect:
    """Compute the minimal axis-aligned rectangle that covers all points.

    :param pts: An iterable of (x, y) points.
    :returns: A bounding rectangle (x0, y0, x1, y1).
    """
    limit: Rect = (INF, INF, -INF, -INF)
    (x0, y0, x1, y1) = limit
    for x, y in pts:
        x0 = min(x0, x)
        y0 = min(y0, y)
        x1 = max(x1, x)
        y1 = max(y1, y)
    return x0, y0, x1, y1


def vecBetweenBoxes(obj1: "LTComponent", obj2: "LTComponent") -> Point:
    """Compute the distance vector between two bounding boxes.

    If the boxes overlap, returns the vector between their centers instead.
    This is used in layout analysis to determine the spacing between
    text components.

             +------+..........+ (x1, y1)
             | obj1 |          :
             +------+www+------+
             :          | obj2 |
    (x0, y0) +..........+------+

    :param obj1: First layout component.
    :param obj2: Second layout component.
    :returns: A (dx, dy) distance vector.
    """
    (x0, y0) = (min(obj1.x0, obj2.x0), min(obj1.y0, obj2.y0))
    (x1, y1) = (max(obj1.x1, obj2.x1), max(obj1.y1, obj2.y1))
    (ow, oh) = (x1 - x0, y1 - y0)
    (iw, ih) = (ow - obj1.width - obj2.width, oh - obj1.height - obj2.height)
    if iw < 0 and ih < 0:
        # One is inside another — compute euclidean distance between centers
        (xc1, yc1) = ((obj1.x0 + obj1.x1) / 2, (obj1.y0 + obj1.y1) / 2)
        (xc2, yc2) = ((obj2.x0 + obj2.x1) / 2, (obj2.y0 + obj2.y1) / 2)
        return xc1 - xc2, yc1 - yc2
    else:
        return max(0, iw), max(0, ih)


# ─── Spatial index ─────────────────────────────────────────────────────────

LTComponentT = TypeVar("LTComponentT", bound="LTComponent")


def _drange(v0: float, v1: float, d: int) -> range:
    """Return a discrete range for grid indexing."""
    return range(int(v0) // d, int(v1 + d) // d)


class Plane(Generic[LTComponentT]):
    """A set-like data structure for objects placed on a 2D plane.

    Can efficiently find objects in a certain rectangular area.
    It maintains two parallel lists of objects, each of which is sorted
    by its x or y coordinate. Uses a grid-based spatial index for
    O(n/k) area queries where k is the grid density.

    :param bbox: The bounding rectangle of the entire plane.
    :param gridsize: The size of each grid cell (default 50 units).
    """

    def __init__(self, bbox: Rect, gridsize: int = 50) -> None:
        self._seq: list[LTComponentT] = []  # preserve the object order.
        self._objs: set[LTComponentT] = set()
        self._grid: dict[Point, list[LTComponentT]] = {}
        self.gridsize = gridsize
        (self.x0, self.y0, self.x1, self.y1) = bbox

    def __repr__(self) -> str:
        return f"<Plane objs={list(self)!r}>"

    def __iter__(self) -> Iterator[LTComponentT]:
        return (obj for obj in self._seq if obj in self._objs)

    def __len__(self) -> int:
        return len(self._objs)

    def __contains__(self, obj: object) -> bool:
        return obj in self._objs

    def _getrange(self, bbox: Rect) -> Iterator[Point]:
        (x0, y0, x1, y1) = bbox
        if x1 <= self.x0 or self.x1 <= x0 or y1 <= self.y0 or self.y1 <= y0:
            return
        x0 = max(self.x0, x0)
        y0 = max(self.y0, y0)
        x1 = min(self.x1, x1)
        y1 = min(self.y1, y1)
        for grid_y in _drange(y0, y1, self.gridsize):
            for grid_x in _drange(x0, x1, self.gridsize):
                yield (grid_x, grid_y)

    def extend(self, objs: Iterable[LTComponentT]) -> None:
        """Add multiple objects to the plane."""
        for obj in objs:
            self.add(obj)

    def add(self, obj: LTComponentT) -> None:
        """Place an object on the plane."""
        for k in self._getrange((obj.x0, obj.y0, obj.x1, obj.y1)):
            if k not in self._grid:
                r: list[LTComponentT] = []
                self._grid[k] = r
            else:
                r = self._grid[k]
            r.append(obj)
        self._seq.append(obj)
        self._objs.add(obj)

    def remove(self, obj: LTComponentT) -> None:
        """Displace an object from the plane."""
        for k in self._getrange((obj.x0, obj.y0, obj.x1, obj.y1)):
            with contextlib.suppress(KeyError, ValueError):
                self._grid[k].remove(obj)
        self._objs.remove(obj)

    def find(self, bbox: Rect) -> Iterator[LTComponentT]:
        """Find all objects that overlap with the given rectangular area."""
        (x0, y0, x1, y1) = bbox
        done = set()
        for k in self._getrange(bbox):
            if k not in self._grid:
                continue
            for obj in self._grid[k]:
                if obj in done:
                    continue
                done.add(obj)
                if obj.x1 <= x0 or x1 <= obj.x0 or obj.y1 <= y0 or y1 <= obj.y0:
                    continue
                yield obj
