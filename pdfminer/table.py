""" Table layout analysis

Extends the layout analysis code in layout.py with support for tables.
"""

from abc import abstractmethod
from bisect import bisect_left, bisect_right
from itertools import chain
from operator import attrgetter

try:
    from statistics import fmean
except ImportError:
    from statistics import mean as fmean

from typing import (
    Tuple,
    List,
    Optional,
    Iterable,
    TypeVar,
    Container,
    Sequence,
    Union,
)

from .layout import (
    LTItem,
    LAParams,
    LTRect,
    LTComponent,
    LTLayoutContainer,
    LTContainer,
    LTCurve,
    LTTextBox,
)
from .utils import pairwise

__all__ = ["analyze_tables", "LTTable", "LTCell"]


def sort_and_cluster(values: Iterable[float], eps: float):
    """Sort all values and merge those that are too close together.

    Clusters of values that are within an eps-distance of each other will
    usually be replaced by their arithmetic mean. Exceptions,
    if len(result) > 1, are the first and the last value in the result, which
    will be the minimum and the maximum, respectively.
    :param values: Numbers, possibly redundant and in arbitrary order.
    :param eps: Values that are within this distance of each other will be
      merged into one.
    :return: List of position values in ascending order, where sets of
      values within self.border_tolerance of each other are replaced by
      their average.
    """
    result: List[float] = []
    to_merge: List[float] = []
    for val in sorted(values):
        if to_merge and val - to_merge[-1] > eps:
            result.append(fmean(to_merge) if result else to_merge[0])
            to_merge.clear()
        to_merge.append(val)
    if to_merge:
        result.append(to_merge[-1] if result else fmean(to_merge))
    return result


class TableBorder:
    """A contiguous, straight line that is potentially part of a table.

    This class is used during table detection to merge parallel and connected
    line segments into one, while remembering the junction points between them.
    """

    def __init__(
        self,
        ortho: float,
        p0: float,
        p1: float,
        linked_element: Optional[LTCurve] = None,
    ):
        self.ortho = ortho
        """ Coordinate in the direction orthogonal to the line
        (y For HTableBorder, x for VTableBorder). We generalize it that way
        because this allows implementing all the TableBorder functionality in
        a common base class. """
        self.positions = [p0, p1]
        """ Coordinates in the direction of the line
        (x For HTableBorder, y for VTableBorder). Sorted in ascending order.
        First element is the start of the line, last element is the end,
        elements in between are points where connecting lines have been merged.
        """
        self.cluster = None
        """ Used only by cluster_table_borders to keep track of which line
        belongs to which cluster/table. """
        self.linked_elements = (
            set() if linked_element is None else {linked_element}
        )
        """ Set of LTRect / LTCurve objects that form this border.
        Used by analyze_tables to group these elements and prevent them from
        getting added into the table cells. """

        self.positions.sort()

    @abstractmethod
    def points(self) -> Iterable[Tuple[float, float]]:
        """ Generator of all points (x,y) on this line. """
        pass

    @property
    def start(self) -> float:
        """Start (lowest) coordinate in the direction of the line
        (x For HTableBorder, y for VTableBorder)."""
        return self.positions[0]

    @property
    def end(self) -> float:
        """End (highest) coordinate in the direction of the line
        (x For HTableBorder, y for VTableBorder)."""
        return self.positions[-1]

    def __str__(self) -> str:
        return (
            f"@{self.ortho:06.2f}: [{len(self.positions):02d}] "
            + " -- ".join(f"{p:06.2f}" for p in self.positions)
        )

    @property
    def length(self) -> float:
        """ Total length of the line """
        return self.positions[-1] - self.positions[0]

    @classmethod
    def merge_all(
        cls, lines: List["TTableBorder"], eps: float
    ) -> List["TTableBorder"]:
        """In a list of table border elements, merge all that can be merged.

        Searches for lines that have the same 'ortho' coordinate (+/- eps) and
        overlapping or connecting 'position's (maximally with a gap of eps).

        :param lines: List of table border elements
        :param eps: Maximum displacement of connecting lines
        :return: The list of remaining, merged line objects, sorted by 'ortho'.
        """
        by_start = sorted(lines, key=attrgetter("start", "end", "ortho"))
        for idx, line in enumerate(by_start):
            if line is not None:
                line._merge_matching(by_start, eps=eps, start_idx=idx + 1)
        return sorted(
            (line for line in by_start if line is not None),
            key=attrgetter("ortho", "start", "end"),
        )

    def _merge_matching(
        self,
        others: List[Optional["TableBorder"]],
        eps: float,
        start_idx: int = 0,
    ):
        """Merge all other matching lines into this one.

        :param others: List of TableBorder lines sorted by 'start'.
        :param eps: Maximum displacement of a line to be merged.
        :param start_idx: Index into 'others', pointing past 'self'

        Since the 'ortho' coordinates of lines being merged can vary (by eps),
        we calculate an average weighted by line length.
        All entries in 'others' that get successfully merged into this line
        are set to None so they can later be removed.
        """
        weighted_ortho_sum = self.ortho * self.length
        length_sum = self.length
        merged = False
        for idx, other in enumerate(others[start_idx:], start=start_idx):
            if other is None or abs(other.ortho - self.ortho) > eps:
                continue
            if other.start > (self.end + eps):
                break

            weighted_ortho_sum += other.ortho * other.length
            length_sum += other.length
            self.linked_elements.update(other.linked_elements)
            other.linked_elements.clear()
            self.positions = sort_and_cluster(
                chain(self.positions, other.positions), eps
            )
            merged = True
            others[idx] = None

        if merged:
            self.ortho = weighted_ortho_sum / length_sum

    def intersects(self, other: "TableBorder", eps: float):
        """Check if an orthogonal line intersects this one

        Ending exactly at this line and missing by a gap of <= eps counts, too.

        :param other: An orthogonal TableBorder line
        :param eps: Maximum gap to still count as "connecting"
        """
        return (
            self.start - eps <= other.ortho <= self.end + eps
            and other.start - eps <= self.ortho <= other.end + eps
        )

    def filter_intersecting(
        self, ortho_lines: Iterable["TTableBorder"], eps: float
    ) -> Iterable["TTableBorder"]:
        """Yield all lines that intersect (or at least connect to) this one

        :param ortho_lines: Iterable of lines orthogonal to self
        :param eps: Maximum gap to still count as "connecting"
        """
        for line in ortho_lines:
            if self.intersects(line, eps):
                yield line

    def adjust_positions(self, other: "TableBorder", eps: float):
        """Adjust self.positions to align with orthogonal lines

        :param other: An orthogonal line of the same cluster
        :param eps: Maximum displacement of an own 'position' to be considered
                    for aligning to 'other.ortho'
        """
        for idx, pos in enumerate(self.positions):
            if pos < other.ortho - eps:
                continue
            elif pos > other.ortho + eps:
                break
            self.positions[idx] = other.ortho

    class OrthoCmp:
        """Helper class for bisecting a list of table borders sorted by ortho.

        This hack can be removed once Python 3.10 is the oldest version
        supported by pdfminer - the bisect functions will then support a key=
        argument.
        """

        def __init__(self, ortho: float):
            self.ortho = ortho

        def __lt__(self, other: Union["TableBorder", "TableBorder.OrthoCmp"]):
            return self.ortho < other.ortho

    def __lt__(self, other: Union["TableBorder", "TableBorder.OrthoCmp"]):
        return self.ortho < other.ortho


class HTableBorder(TableBorder):
    """A horizontal line that is potentially part of a table.

    This class doesn't really add any functionality to its base class, but it
    is useful with type checking to prevent accidental mixing of horizontal
    and vertical lines.
    """

    def points(self):
        for pos in self.positions:
            yield (pos, self.ortho)

    def intersects(self, other: "VTableBorder", eps: float):
        return isinstance(other, VTableBorder) and super().intersects(
            other, eps
        )


class VTableBorder(TableBorder):
    """A vertical line that is potentially part of a table.

    This class doesn't really add any functionality to its base class, but it
    is useful with type checking to prevent accidental mixing of horizontal
    and vertical lines.
    """

    def points(self):
        for pos in self.positions:
            yield (self.ortho, pos)

    def intersects(self, other: "HTableBorder", eps: float):
        return isinstance(other, HTableBorder) and super().intersects(
            other, eps
        )


# Either a horizontal or a vertical table border. This TypeVar is typically
# used to express that a function will return the same type of table border as
# its argument was.
TTableBorder = TypeVar("TTableBorder", HTableBorder, VTableBorder)


def find_table_borders(elements: Iterable[LTItem], laparams: LAParams):
    """Find the potential table borders among all elements of a page.

    :param elements: Iterable of elements on the page
    :param laparams: Layout analysis parameters
    :return: A list of horizontal borders and a list of vertical borders
    """
    hborders = []
    vborders = []
    for elt in elements:
        if isinstance(elt, LTRect):
            # Some software seems to generate thin rectangles as table borders.
            if elt.width < laparams.table_border_maxwidth:
                if elt.height < laparams.table_border_maxwidth:
                    continue
                mid = (elt.x0 + elt.x1) * 0.5
                vborders.append(VTableBorder(mid, elt.y0, elt.y1, elt))
            if elt.height < laparams.table_border_maxwidth:
                mid = (elt.y0 + elt.y1) * 0.5
                hborders.append(HTableBorder(mid, elt.x0, elt.x1, elt))
        elif isinstance(elt, LTCurve):
            if elt.linewidth > laparams.table_border_maxwidth:
                continue
            for (x0, y0), (x1, y1) in pairwise(elt.pts):
                dx = abs(x1 - x0)
                dy = abs(y1 - y0)
                if dy < laparams.table_border_tolerance < dx:
                    hborders.append(HTableBorder((y0 + y1) * 0.5, x0, x1, elt))
                elif dx < laparams.table_border_tolerance < dy:
                    vborders.append(VTableBorder((x0 + x1) * 0.5, y0, y1, elt))

    hborders = TableBorder.merge_all(hborders, laparams.table_border_maxwidth)
    vborders = TableBorder.merge_all(vborders, laparams.table_border_maxwidth)
    return hborders, vborders


def cluster_table_borders(
    hborders: Iterable[HTableBorder],
    vborders: Iterable[VTableBorder],
    laparams: LAParams,
):
    """Find clusters of intersecting border lines.

    This is the next processing step after find_table_borders.
    Each returned cluster corresponds to one table on the page.
    These can then be passed to the LTTable constructor.

    :param hborders: The horizontal borders found on the page
    :param vborders: The vertical borders found on the page
    :param laparams: Layout analysis parameters
    :return: Lists of horizontal and vertical borders, for each table
    """
    clusters: List[Tuple[List[HTableBorder], List[VTableBorder]]] = []
    tol = laparams.table_border_tolerance
    for hborder in hborders:
        for vborder in hborder.filter_intersecting(vborders, tol):
            if hborder.cluster is None:
                clusters.append(([hborder], []))
                hborder.cluster = clusters[-1]
            if vborder.cluster is None:
                hborder.cluster[1].append(vborder)
                vborder.cluster = hborder.cluster
            hborder.adjust_positions(vborder, tol)
            for hborder2 in vborder.filter_intersecting(hborders, tol):
                if hborder2.cluster is None:
                    hborder.cluster[0].append(hborder2)
                    hborder2.cluster = hborder.cluster
    for vborder in vborders:
        for hborder in vborder.filter_intersecting(hborders, tol):
            vborder.adjust_positions(hborder, tol)
    return clusters


class LTCell(LTLayoutContainer):
    """A cell within a table"""

    _bleft: Optional[bool]
    _btop: Optional[bool]
    _bright: Optional[bool]
    _bbottom: Optional[bool]

    def __init__(
        self,
        table: "LTTable",
        col: int,
        row: int,
        colspan: int = 1,
        rowspan: int = 1,
        bbox: Optional[Tuple[float, float, float, float]] = None,
    ):
        self.table = table
        """ The LTTable that contains this cell. This is used to ask the table
        for the cell's bounding box, to determine cell border lines and even to
        manipulate the table when merging cells. """
        self.col = col
        """ Starting (leftmost) column of this cell, 0-based. """
        self.row = row
        """ Starting (topmost) row of this cell, 0-based. """
        self.colspan = colspan
        """ Column span of this cell, like in HTML. >= 1. """
        self.rowspan = rowspan
        """ Row span of this cell, like in HTML. >= 1. """
        self.analyzed = False
        """ Whether (text) layout analysis of this cell's contents has already
        happened.
        """

        super().__init__(bbox if bbox is not None else self.calculate_bbox())

    def set_bbox(self, bbox):
        super().set_bbox(bbox)
        self._bleft = None
        self._btop = None
        self._bright = None
        self._bbottom = None

    @property
    def border_left(self):
        """Whether this cell has a left border line.
        Lazy evaluation: The result is cached at the first call and reset when
        the bounding box changes, e.g. due to splitting/merging."""
        if self._bleft is None:
            self._bleft = self.table.vborder_at(self.x0, self.y0, self.y1)
        return self._bleft

    @property
    def border_top(self):
        """Whether this cell has a top border line.
        Lazy evaluation: The result is cached at the first call and reset when
        the bounding box changes, e.g. due to splitting/merging."""
        if self._btop is None:
            self._btop = self.table.hborder_at(self.y1, self.x0, self.x1)
        return self._btop

    @property
    def border_right(self):
        """Whether this cell has a right border line.
        Lazy evaluation: The result is cached at the first call and reset when
        the bounding box changes, e.g. due to splitting/merging."""
        if self._bright is None:
            self._bright = self.table.vborder_at(self.x1, self.y0, self.y1)
        return self._bright

    @property
    def border_bottom(self):
        """Whether this cell has a bottom border line.
        Lazy evaluation: The result is cached at the first call and reset when
        the bounding box changes, e.g. due to splitting/merging."""
        if self._bbottom is None:
            self._bbottom = self.table.hborder_at(self.y0, self.x0, self.x1)
        return self._bbottom

    @property
    def colrange(self):
        """ Range of column indices that this cell spans. """
        return range(self.col, self.col + self.colspan)

    @property
    def rowrange(self):
        """ Range of row indices that this cell spans. """
        return range(self.row, self.row + self.rowspan)

    def merge_right(self):
        """Merge this cell with the one(s) to the right.

        The other cells' contents are moved to this one, the corresponding
        entries in the table's cells lists are overwritten with references to
        this cell and the colspan value and bounding box are updated.

        If there is no other cell left that starts or ends at the column border
        where this one used to end, that column border is removed from the
        table and all indices adjusted accordingly. Since this modifies the
        table's cells lists,
        DO NOT CALL THIS METHOD WHILE ITERATING THE TABLE CELLS!
        """
        for row in self.rowrange:
            neighbor = self.table[row, self.col + self.colspan]
            if neighbor is not self:
                self.extend(neighbor)
                self.table[row, self.col + self.colspan] = self

        spanned_col = self.col + self.colspan - 1
        self.colspan += 1
        if not any(
            cell.col + cell.colspan == spanned_col + 1
            for cell in self.table[:, spanned_col]
        ):
            self.table.remove_col(spanned_col)

        self.set_bbox(self.calculate_bbox())

    def merge_down(self):
        """Merge this cell with the one(s) below.

        The other cells' contents are moved to this one, the corresponding
        entries in the table's cells lists are overwritten with references to
        this cell and the rowspan value and bounding box are updated.

        If there is no other cell left that starts or ends at the row border
        where this one used to end, that row border is removed from the table
        and all indices adjusted accordingly. Since this modifies the table's
        cells lists, DO NOT CALL THIS METHOD WHILE ITERATING THE TABLE CELLS!
        """
        for col in self.colrange:
            neighbor = self.table[self.row + self.rowspan, col]
            if neighbor is not self:
                self.extend(neighbor)
                self.table[self.row + self.rowspan, col] = self

        spanned_row = self.row + self.rowspan - 1
        self.rowspan += 1
        if not any(
            cell.row + cell.rowspan == spanned_row + 1
            for cell in self.table[spanned_row, :]
        ):
            self.table.remove_row(spanned_row)

        self.set_bbox(self.calculate_bbox())

    def calculate_bbox(self):
        """Update the cell's bounding box

        Ask the table to look up the positions of the respective columns and
        rows.
        """
        x0, y1 = self.table.cell_to_point(self.col, self.row)
        x1, y0 = self.table.cell_to_point(
            self.col + self.colspan, self.row + self.rowspan
        )
        return x0, y0, x1, y1

    def detach_objs(self):
        """Detach all child objects from this cell and return them.

        The internal list of child objects is cleared.
        """
        result = self._objs
        self._objs = []
        return result

    def add(self, obj):
        if not hasattr(obj, "_table_add_index"):
            setattr(obj, "_table_add_index", None)
        self.analyzed = False
        super().add(obj)

    def analyze(self, laparams: LAParams):
        if self.analyzed:
            return
        try:
            self._objs.sort(key=attrgetter("_table_add_index"))
        except AttributeError:
            # If analyze is called twice, analysis artifacts from the first run
            # may have been added without setting _table_add_index. In that
            # case, _objs is already sorted, so we can ignore this.
            pass
        super().analyze(laparams)
        self.analyzed = True

    def analyze_tables(self, elements: List[LTItem], _laparams: LAParams):
        # Table cells are layout containers, so they will run the full analysis
        # algorithm. We don't want to waste effort looking for nested tables
        # though, so we override this part of the analysis with a dummy.
        return ([], elements)

    def get_text(self):
        """After analysis, get all the text from this cell.

        Returns a concatenation of all LTTextBox texts found within the cell,
        with some unnecessary whitespace removed.
        """
        return "".join(
            element.get_text().replace(" \n", "\n")
            for element in self
            if isinstance(element, LTTextBox)
        ).strip()


class LTTable(LTContainer):
    """A table.

    The table consists of a regular grid (List of Lists) of LTCell objects.
    Multiple entries in the grid may refer to the same object if that cell
    has a colspan or rowspan >1.
    The table also holds lists of the positions of column and row borders in
    the page, and lists of border lines used to determine cell borders.
    """

    def __init__(
        self,
        hborders: List[HTableBorder],
        vborders: List[VTableBorder],
        laparams: LAParams,
    ):
        self.hborders = hborders
        """ List of all horizontal border lines in this table, sorted by
        their 'ortho' attribute """
        self.vborders = vborders
        """ List of all vertical border lines in this table, sorted by
        their 'ortho' attribute """
        self.border_tolerance = laparams.table_border_tolerance
        """ Cell border tolerance value used in layout analysis. """
        self.column_positions = sort_and_cluster(
            chain(
                (line.ortho for line in self.vborders),
                chain.from_iterable(line.positions for line in self.hborders),
            ),
            self.border_tolerance,
        )
        """ x positions of all column borders, sorted left to right.
        column_position[0] is the left table border. The left and right borders
        of column n are column_position[n] and [n+1]. column_position[-1] is
        the right table border.
        """
        self.row_positions = sort_and_cluster(
            chain(
                (line.ortho for line in self.hborders),
                chain.from_iterable(line.positions for line in self.vborders),
            ),
            self.border_tolerance,
        )
        """ y positions of all row borders, sorted bottom to top (!).
        row_positions[0] is the bottom table border. The top and bottom borders
        of row n are row_positions[-1-n] and [-2-n]. row_positions[-1] is the
        top table border.
        The odd sorting order (reversed wrt the top-down _cells list) was
        chosen to allow searching with bisect.
        """
        self._cells = [
            [
                LTCell(self, col, row, bbox=(x0, y0, x1, y1))
                for col, (x0, x1) in enumerate(pairwise(self.column_positions))
            ]
            for row, (y1, y0) in enumerate(
                pairwise(reversed(self.row_positions))
            )
        ]
        """ _cells[row][col] holds the LTCell object that belongs to that table
        cell.
        """
        self._add_index = 0
        """ Counter for all elements added to the table cells. This allows
        restoring the original order even after splitting or merging cells. The
        order is relevant for text layout analysis.
        """
        super().__init__(
            (
                self.column_positions[0],
                self.row_positions[0],
                self.column_positions[-1],
                self.row_positions[-1],
            )
        )

    def border_at(
        self,
        borders: Sequence[TTableBorder],
        ortho: float,
        pos0: float,
        pos1: float,
    ):
        """Check if there is a border line at a given position.

        :param borders: A sequence of table borders
        :param ortho: The position (orthogonal to the direction of the line) to
          search at, +/- self.border_tolerance
        :param pos0: The position (in the direction of the line) where the line
          must start, + self.border_tolerance
        :param pos1: The position (in the direction of the line) where the line
          must reach, - self.border_tolerance
        :return: True iff any such line was found.
        """
        lo = bisect_left(
            borders, TableBorder.OrthoCmp(ortho - self.border_tolerance)
        )
        hi = bisect_right(
            borders, TableBorder.OrthoCmp(ortho + self.border_tolerance), lo
        )
        return any(
            border.positions[0] - self.border_tolerance <= pos0
            and border.positions[-1] + self.border_tolerance >= pos1
            for border in borders[lo:hi]
        )

    def hborder_at(self, y, x0, x1):
        """Check if there is a horizontal border at a given position.

        This is used to check if a given cell has a top or bottom border line
        that spans from the left to the right corner.
        :param y: The y position to search at, i.e. the cell's bottom or top.
        :param x0: The x position where the line must start, i.e. the cell's
          left.
        :param x1: The x position where the line must reach, i.e. the cell's
          right.
        :return: True iff any such line was found.
        """
        return self.border_at(self.hborders, y, x0, x1)

    def vborder_at(self, x, y0, y1):
        """Check if there is a vertical border at a given position.

        This is used to check if a given cell has a left or right border line
        that spans from the bottom to the top corner.
        :param x: The x position to search at, i.e. the cell's left or right.
        :param y0: The y position where the line must start, i.e. the cell's
          bottom.
        :param y1: The y position where the line must reach, i.e. the cell's
          top.
        :return: True iff any such line was found.
        """
        return self.border_at(self.vborders, x, y0, y1)

    def __iter__(self):
        """Generator that yields each cell of the table exactly once.

        Cells appear in left-to-right, then top-down order. Each cell appears
        only once, even if it spans multiple columns/rows.
        Uses rather un-pythonic while loops so it doesn't break in case the
        cell arrays are modified.
        """
        row = 0
        while row < len(self._cells):
            col = 0
            while col < len(self._cells[row]):
                cell = self._cells[row][col]
                if cell.col == col and cell.row == row:
                    yield cell
                col += 1
            row += 1

    def iter_region(
        self,
        rows: Union[int, slice, Iterable[int]],
        cols: Union[int, slice, Iterable[int]],
    ):
        """Generator that yields each cell of the given region exactly once.

        Unlike __iter__, this considers only the rows given in the rows
        parameter, and in each such row, only the columns given in the cols
        parameter. Colspan/rowspan cells are considered as long as they contain
        at least one of these cells.
        Cells appear in left-to-right, then top-down order. Each cell appears
        only once, even if it spans multiple columns/rows.
        :param rows: row index, slice or iterable of row indices
        :param cols: column index, slice or iterable of column indices
        :return:
        """
        if isinstance(rows, int):
            rows = (rows,)
        elif isinstance(rows, slice):
            rows = range(*rows.indices(len(self._cells)))

        if isinstance(cols, int):
            cols = (cols,)
        elif isinstance(cols, slice):
            cols = range(*cols.indices(len(self._cells[0])))

        seen = set()
        for row in rows:
            for col in cols:
                cell = self._cells[row][col]
                if cell not in seen:
                    yield cell
                    seen.add(cell)

    def __getitem__(self, item):
        """Get a cell or region by row/column indices

        Tables can be subscripted with a single index, which is equivalent to
        subscripting the _cells List of rows, or with a 2-tuple (col, row).
        If (col, row) are both ints, this returns the corresponding cell.
        Otherwise, i.e. if one or both indices are slices or Iterables of
        indices, this method calls iter_region to return a generator of cells.
        """
        if isinstance(item, (int, slice)):
            return self._cells[item]
        elif isinstance(item, tuple):
            row, col = item
            if isinstance(row, int) and isinstance(col, int):
                return self._cells[row][col]
            else:
                return self.iter_region(row, col)
        else:
            raise TypeError(
                "Table indices must be integers or tuples of two integers, "
                f"not {type(item)}"
            )

    def __setitem__(self, key, value):
        """ Assign a row, or a cell, with some type checking """
        if isinstance(key, int):
            if not (
                isinstance(value, list)
                and len(value) == self.num_cols
                and all(isinstance(cell, LTCell) for cell in value)
            ):
                raise TypeError(
                    "A table row must be a list of LTCell with num_cols "
                    f"(={self.num_cols}) items"
                )
            self._cells[key] = value
        elif isinstance(key, tuple) and len(key) == 2:
            if not isinstance(value, LTCell):
                raise TypeError(
                    f"A table cell must be an LTCell, not {type(value)}"
                )
            self._cells[key[0]][key[1]] = value
        else:
            raise TypeError(
                "Table indices must be integers or tuples of two integers, "
                f"not {type(key)}"
            )

    @property
    def num_cols(self):
        """ Number of columns """
        return len(self._cells[0]) if self._cells else 0

    @property
    def num_rows(self):
        """ Number of rows """
        return len(self._cells)

    def __len__(self):
        """Get the number of cells in the table, counting span cells only once

        Counts the number of cells returned by __iter__.
        """
        return sum(1 for _ in self)

    def point_to_cell(self, x: float, y: float) -> Tuple[int, int]:
        """For a given point, determine the corresponding table cell.

        Raises ValueError for points outside the table.
        :param x: X coordinate.
        :param y: Y coordinate.
        :return: A (column, row) tuple.
        """
        col = bisect_left(self.column_positions, x)
        row = bisect_left(self.row_positions, y)
        if 0 < col < len(self.column_positions) and 0 < row < len(
            self.row_positions
        ):
            return col - 1, len(self.row_positions) - row - 1
        raise ValueError(f"Point ({x:.02f}, {y:.02f}) is outside the table")

    def cell_to_point(self, col: int, row: int):
        """For a given table cell, get the position of the top-left corner.
        Passing (num_cols, num_rows) is allowed to get the table's bottom-right
        corner.
        :param col: Column number.
        :param row: Row number.
        :return: An (x, y) tuple.
        """
        return self.column_positions[col], self.row_positions[-1 - row]

    def add(self, obj):
        """Add an element to the table.
        This adds the element to the correct cell (determined by the element's
        center point) or raises a ValueError if the element lies outside the
        table.
        """
        if isinstance(obj, LTTable) or isinstance(obj, LTCell):
            raise NotImplementedError("Cannot merge tables yet")
        elif isinstance(obj, LTComponent):
            col, row = self.point_to_cell(
                (obj.x0 + obj.x1) * 0.5, (obj.y0 + obj.y1) * 0.5
            )

            # The order in which characters have been read from the PDF file
            # seems to be important for text analysis. It gets mixed up when
            # objects are distributed to cells and later some cells are merged.
            # So better remember the order in which they were added originally.
            setattr(obj, "_table_add_index", self._add_index)
            self._add_index += 1

            self._cells[row][col].add(obj)
        else:
            raise TypeError(
                "Can only add LTComponents to a table, since we need to know "
                "an x,y position to find the correct cell to add to"
            )

    def analyze(self, laparams):
        for obj in self:
            obj.analyze(laparams)
        return

    def split_row(self, y: float, cols: Optional[Container[int]] = None):
        """Split a table row, possibly only in certain columns

        Cells in this row that are not split will have their rowspan increased
        instead.
        Since this method modifies the table's cells list,
        DO NOT CALL THIS WHILE ITERATING CELLS!

        :param y: The y position of the new grid line. The row to be split is
          determined automatically.
        :param cols: The column indices where cells shall be split, or None to
          split all columns. Colspan cells will be split if they contain at
          least one of the cols indices.
        """
        row = len(self.row_positions) - bisect_left(self.row_positions, y) - 1
        if not 0 <= row < self.num_rows:
            raise ValueError(f"y={y:.02f} is outside the table")

        # Start by cloning the row - new List, same LTCell references.
        newrow = list(self._cells[row])
        self._cells.insert(row + 1, newrow)
        # pycodestyle and black disagree about spaces in complex slices.
        # It seems pycodestyle is wrong.
        # todo: remove the noqa here and in split_col when pycodestyle is fixed
        #       or when the broken E203 check is disabled project-wide.
        for cell in self[row + 1 :, :]:  # noqa: E203
            if cell.row > row:
                cell.row += 1
            elif cell.row + cell.rowspan > row:
                cell.rowspan += 1
        # Insert a new row border
        self.row_positions.insert(-1 - row, y)

        for col in range(len(newrow)):
            oldcell = self._cells[row][col]

            if col != oldcell.col:
                # For cells with a colspan, do the processing only once in the
                # leftmost column; in further columns just copy the cell
                # reference from the first column.
                newrow[col] = newrow[oldcell.col]
                continue

            if not (cols is None or any(n in cols for n in oldcell.colrange)):
                continue
            # Proceed only if this cell spans one of the columns to be split.

            # Create a new cell object that starts at [row+1] and spans down
            # to where oldcell ended.
            newrow[col] = LTCell(
                self,
                col,
                row + 1,
                oldcell.colspan,
                oldcell.row + oldcell.rowspan - (row + 1),
            )
            # Now trim oldcell so that it ends in [row].
            oldcell.rowspan = row + 1 - oldcell.row
            oldcell.set_bbox(oldcell.calculate_bbox())
            # Remove the contents of oldcell and add them back to one of the
            # cells according to y position.
            for obj in oldcell.detach_objs():
                mid = (obj.y0 + obj.y1) * 0.5
                (oldcell if mid > y else newrow[col]).add(obj)

    def split_col(self, x: float, rows: Optional[Container[int]] = None):
        """Split a table column, possibly only in certain rows

        Cells in this column that are not split will have their colspan
        increased instead.
        Since this method modifies the table's cells list,
        DO NOT CALL THIS WHILE ITERATING CELLS!

        :param x: The x position of the new grid line. The column to be split
          is determined automatically.
        :param rows: The row indices where cells shall be split, or None to
          split all rows. Rowspan cells will be split if they contain at
          least one of the rows indices.
        """
        col = bisect_left(self.column_positions, x) - 1
        if not 0 <= col < self.num_cols:
            raise ValueError(f"x={x:.02f} is outside the table")

        # Start by cloning the column.
        for row in self._cells:
            row.insert(col + 1, row[col])
        for cell in self[:, (col + 1) :]:  # noqa: E203
            if cell.col > col:
                cell.col += 1
            elif cell.col + cell.colspan > col:
                cell.colspan += 1
        # Insert a new row border
        self.column_positions.insert(col + 1, x)

        for nrow, row in enumerate(self._cells):
            oldcell = row[col]
            if nrow != oldcell.row:
                # For cells with a rowspan, do the processing only once in the
                # topmost row; in further rows just copy the cell reference
                # from the first row.
                row[col + 1] = self._cells[oldcell.row][col + 1]
                continue

            if not (
                rows is None or any(irow in rows for irow in oldcell.rowrange)
            ):
                continue
            # Proceed only if this cell spans one of the rows to be split.

            # Create a new cell object that starts at [col+1] and spans to the
            # right up to where oldcell ended.
            row[col + 1] = LTCell(
                self,
                col + 1,
                nrow,
                oldcell.col + oldcell.colspan - (col + 1),
                oldcell.rowspan,
            )
            # Now trim oldcell so that it ends in [col].
            oldcell.colspan = col + 1 - oldcell.col
            oldcell.set_bbox(oldcell.calculate_bbox())
            # Remove the contents of oldcell and add them back to one of the
            # cells according to x position.
            for obj in oldcell.detach_objs():
                mid = (obj.x0 + obj.x1) * 0.5
                (oldcell if mid < x else row[col + 1]).add(obj)

    def remove_row(self, row: int):
        """Remove a row from the table, updating affected cell indices.
        Only to be called by LTCell.merge_down once no cell ends in this row
        any more."""
        for cell in self[row:, :]:
            if cell.row > row:
                cell.row -= 1
            elif cell.row + cell.rowspan > row:
                cell.rowspan -= 1
        del self._cells[row]
        del self.row_positions[-2 - row]

    def remove_col(self, col: int):
        """Remove a column from the table, updating affected cell indices.
        Only to be called by LTCell.merge_right once no cell ends in this
        column any more."""
        for cell in self[:, col:]:
            if cell.col > col:
                cell.col -= 1
            elif cell.col + cell.colspan > col:
                cell.colspan -= 1
        for row in self._cells:
            del row[col]
        del self.column_positions[col + 1]


def analyze_tables(
    container: LTLayoutContainer, elements: List[LTItem], laparams: LAParams
) -> Tuple[List[LTTable], List[LTItem]]:
    """Run the table analysis for a page.

    Looks for graphical elements that may be part of a table grid, clusters
    them and creates table objects accordingly. Adds all other elements whose
    coordinates fall into a table cell to the respective cell.
    At that point, the laparams.table_postprocess callback is called to handle
    e.g. cell merging and splitting.
    Finally, when the cells are set up correctly, analyze_tables runs layout
    analysis on each table cell to find the text contents.

    :param elements: List of all elements to analyze.
    :param laparams: Layout analysis parameters.
    :return: A list of tables and a list of all other elements outside the
      tables.
    """
    tables = []
    border_elements = set()
    for hborders, vborders in cluster_table_borders(
        *find_table_borders(elements, laparams), laparams=laparams
    ):
        tables.append(LTTable(hborders, vborders, laparams))
        for border in chain(hborders, vborders):
            border_elements.update(border.linked_elements)
            border.linked_elements.clear()

    otherobjs = []
    for element in elements:
        if element in border_elements:
            otherobjs.append(element)
            continue

        not_in_table = True
        for table in tables:
            try:
                table.add(element)
                not_in_table = False
                break
            except ValueError:
                pass

        if not_in_table:
            otherobjs.append(element)

    for table in tables:
        if laparams.table_postprocess is not None:
            laparams.table_postprocess(container, table, laparams)
        table.analyze(laparams)

    return tables, otherobjs
