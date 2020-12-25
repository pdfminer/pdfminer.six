from typing import Optional, List

import pytest

from helpers import absolute_sample_path
from pdfminer.high_level import extract_pages
from pdfminer.layout import (
    LAParams,
    LTChar,
    LTPage,
    LTTextBox,
    LTLine,
    LTLayoutContainer,
)

# noinspection PyProtectedMember
from pdfminer.table import (
    sort_and_cluster,
    HTableBorder,
    VTableBorder,
    LTTable,
)
from pdfminer.utils import FloatIntervals, pairwise


class TestHelpers:
    """ Test helper functions in table.py"""

    @pytest.mark.parametrize(
        "values,eps,expected",
        [
            ([1.0, 2.0, 3.0, 4.0], 0.5, [1.0, 2.0, 3.0, 4.0]),
            ([1.0, 2.0, 3.0, 4.0], 1.0, [2.5]),
            ([2.0, 4.0, 6.0, 1.5, 3.5], 1.0, [1.5, 3.75, 6.0]),
        ],
    )
    def test_sort_and_cluster(self, values, eps, expected):
        assert sort_and_cluster(values, eps) == expected


class TestTableBorders:
    """ Test the basic functionality of the TableBorder class """

    def test_properties(self):
        """ Test that basic properties are calculated correctly """
        hborder = HTableBorder(42.0, 13.0, 37.0)
        assert hborder.start == 13.0
        assert hborder.end == 37.0
        assert hborder.length == (37.0 - 13.0)
        assert list(hborder.points()) == [(13.0, 42.0), (37.0, 42.0)]
        vborder = VTableBorder(42.0, 13.0, 37.0)
        assert list(vborder.points()) == [(42.0, 13.0), (42.0, 37.0)]

    def test_merge(self):
        """ Test that the merge_all method correctly connects borders """

        borders = [
            HTableBorder(1.0, 1.0, 1.9),
            HTableBorder(1.0, 2.0, 2.9),
            HTableBorder(2.0, 2.0, 2.9),
            HTableBorder(1.0, 3.0, 3.9),
            HTableBorder(1.0, 3.9, 4.0),
            HTableBorder(2.0, 3.0, 3.9),
            HTableBorder(2.0, 5.0, 6.0),
        ]
        result = [
            list(border.points())
            for border in HTableBorder.merge_all(borders, 0.2)
        ]
        print(result)
        assert result == [
            [(1.0, 1.0), (1.95, 1.0), (2.95, 1.0), (4.0, 1.0)],
            [(2.0, 2.0), (2.95, 2.0), (3.9, 2.0)],
            [(5.0, 2.0), (6.0, 2.0)],
        ]

    def test_intersects(self):
        """ Test the check for border intersection. """
        # A simple square of lines that don't quite touch each other
        h = [HTableBorder(0.9, 1.1, 1.9), HTableBorder(2.1, 1.1, 1.9)]
        v = [VTableBorder(0.9, 1.1, 1.9), VTableBorder(2.1, 1.1, 1.9)]
        for hborder in h:
            for vborder in v:
                assert hborder.intersects(vborder, 0.201)
                assert not hborder.intersects(vborder, 0.199)
                assert vborder.intersects(hborder, 0.201)
                assert not vborder.intersects(hborder, 0.199)

        for hborder in h:
            assert list(hborder.filter_intersecting(v, 0.201)) == v
            assert list(hborder.filter_intersecting(v, 0.199)) == []
        for vborder in v:
            assert list(vborder.filter_intersecting(h, 0.201)) == h
            assert list(vborder.filter_intersecting(h, 0.199)) == []


def make_table(
    x0: float, y0: float, rowheights: List[float], colwidths: List[float]
):
    """Create table borders for a mock table.

    :param x0: X coordinate of the bottom-left corner of the table
    :param y0: Y coordinate of the bottom-left corner of the table
    :param rowheights: Table row heights, starting at row 0
    :param colwidths:  Table column widths, starting at column 0
    :return: A list of horizontal borders and a list of vertical borders.
    """
    h = [
        HTableBorder(
            y0 + sum(rowheights[row:]),
            x0 + sum(colwidths[:col]),
            x0 + sum(colwidths[: col + 1]),
        )
        for row in range(len(rowheights), -1, -1)
        for col in range(len(colwidths))
    ]
    v = [
        VTableBorder(
            x0 + sum(colwidths[:col]),
            y0 + sum(rowheights[row:]),
            y0 + sum(rowheights[row + 1 :]),  # noqa: E203
        )
        for col in range(len(colwidths) + 1)
        for row in range(len(rowheights) - 1, -1, -1)
    ]
    return h, v


def check_table(table: LTTable):
    """pytest assertion helper: Check a table for internal consistency.

    Currently checks the column/row number and colspan/rowspan of each cell
    to be consistent with their index in the table's internal array and to
    add up corectly across the whole table.
    """
    __tracebackhide__ = True
    n_grid_cells = 0
    n_unique_cells = 0
    for row in range(table.num_rows):
        for col in range(table.num_cols):
            cell = table[row, col]
            if row == cell.row and col == cell.col:
                n_grid_cells += cell.rowspan * cell.colspan
                n_unique_cells += 1
            elif row not in cell.rowrange or col not in cell.colrange:
                pytest.fail(
                    f"cell at [{row}, {col}] actually has "
                    f"row {cell.row} (span {cell.rowspan}), "
                    f"col {cell.col} (span {cell.colspan})"
                )

    if n_unique_cells != len(table):
        pytest.fail(
            f"Table has len {len(table)}, but we counted {n_unique_cells} "
            "unique cells"
        )
    if n_grid_cells != table.num_rows * table.num_cols:
        pytest.fail(
            f"Table grid has {table.num_rows}*{table.num_cols} = "
            f"{table.num_rows * table.num_cols} cells, but sum of "
            f"colspan*rowspan is {n_grid_cells}"
        )


class TestSingleCell:
    """ Tests on functionality of an individual table cell. """

    laparams = LAParams(table_border_tolerance=0.25)
    h, v = make_table(1.0, 2.0, [2.0], [2.0])

    def test_parameters(self):
        """ Test that the cell's properties are calculated correctly """

        table = LTTable(self.h[:], self.v[:], self.laparams)
        assert table.bbox == (1.0, 2.0, 3.0, 4.0)
        assert table.num_rows == 1
        assert table.num_cols == 1
        check_table(table)
        cell = table[0, 0]
        assert cell.bbox == (1.0, 2.0, 3.0, 4.0)
        assert cell.col == 0
        assert cell.colspan == 1
        assert list(cell.colrange) == [0]
        assert cell.row == 0
        assert cell.rowspan == 1
        assert list(cell.rowrange) == [0]
        assert list(cell) == []
        assert cell.get_text() == ""

    @pytest.mark.parametrize(
        "h,v", [(h[1:], v[:]), (h[:0], v[:]), (h[:], v[1:]), (h[:], v[:0])]
    )
    def test_borders(self, h, v):
        """Test checking for border lines around the cell.

        This test is run four times, with one of the four border lines missing
        each time.
        """
        table = LTTable(h, v, self.laparams)
        assert table.num_rows == 1
        assert table.num_cols == 1
        cell = table[0, 0]
        assert cell.border_bottom == (self.h[0] in h)
        assert cell.border_top == (self.h[1] in h)
        assert cell.border_left == (self.v[0] in v)
        assert cell.border_right == (self.v[1] in v)


class TestTable:
    """Tests of more complex table functionality.

    These tests are run on a mock 3x3 table.
    Merging of cells
    Splitting of cells
    """

    laparams = LAParams(table_border_tolerance=0.25)
    h, v = make_table(1.0, 2.0, [3.0, 4.0, 5.0], [6.0, 7.0, 8.0])

    def test_merge_right(self):
        """Test merging cells to the right.

        In a 3x3 table, merges the cells of the center column to the right.
        In the last step, this should remove the whole center-right border
        and thus reduce the column number to 2 and the colspans back to 1.
        """
        table = LTTable(self.h[:], self.v[:], self.laparams)

        table[1, 1].merge_right()
        check_table(table)
        assert len(table) == 8
        assert table.num_cols == 3
        assert table[1, 1].colspan == 2

        table[0, 1].merge_right()
        check_table(table)
        assert len(table) == 7
        assert table.num_cols == 3
        assert table[0, 1].colspan == 2

        table[2, 1].merge_right()
        check_table(table)
        assert len(table) == 6
        assert table.num_cols == 2
        assert table[0, 1].colspan == 1
        assert table[1, 1].colspan == 1
        assert table[2, 1].colspan == 1

    def test_merge_down(self):
        """Test merging cells down.

        In a 3x3 table, merges the cells of the middle row down. In the last
        step, this should remove the whole lower-middle border and thus reduce
        the row number to 2 and the rowspans back to 1.
        """

        table = LTTable(self.h[:], self.v[:], self.laparams)

        table[1, 1].merge_down()
        check_table(table)
        assert len(table) == 8
        assert table.num_rows == 3
        assert table[1, 1].rowspan == 2

        table[1, 0].merge_down()
        check_table(table)
        assert len(table) == 7
        assert table.num_rows == 3
        assert table[1, 0].rowspan == 2

        table[1, 2].merge_down()
        check_table(table)
        assert len(table) == 6
        assert table.num_rows == 2
        assert table[1, 0].rowspan == 1
        assert table[1, 1].rowspan == 1
        assert table[1, 2].rowspan == 1

    def test_split_col(self):
        """Test splitting (some cells of) a column.

        Splits the top and middle cells of the center column in half.
        """
        table = LTTable(self.h[:], self.v[:], self.laparams)
        table.split_col(10.5, [0, 1])
        check_table(table)
        assert len(table) == 11
        assert table.num_cols == 4
        assert table[0, 1] != table[0, 2]
        assert table[1, 1] != table[1, 2]
        assert table[2, 1] == table[2, 2]
        assert table[2, 1].colspan == 2

    def test_split_row(self):
        """Test splitting (some cells of) a row.

        Splits the left and center cells of the middle row in half.
        """
        table = LTTable(self.h[:], self.v[:], self.laparams)
        table.split_row(9.0, [0, 1])
        check_table(table)
        assert len(table) == 11
        assert table.num_rows == 4
        assert table[1, 0] != table[2, 0]
        assert table[1, 1] != table[2, 1]
        assert table[1, 2] == table[2, 2]
        assert table[1, 2].rowspan == 2


class TestDetectTables:
    """Tests of the whole table layout analysis, run on sample PDFs

    These tests also implicitly test the find_table_borders,
    cluster_table_borders and analyze_tables functions, which are not
    unit-tested individually.
    """

    @staticmethod
    def table1_postproc(
        _container: LTLayoutContainer, table: LTTable, _laparams: LAParams
    ):
        """ Post-processing callback for the table in table1.pdf """

        # Do what merge_if_no_border does, but not for certain columns
        # (except in the table header)
        for cell in table:
            while (
                (cell.row <= 1 or cell.col < 7)
                and cell.col + cell.colspan < table.num_cols
                and not cell.border_right
            ):
                cell.merge_right()
            while (
                (cell.row < 1 or cell.col <= 7)
                and cell.row + cell.rowspan < table.num_rows
                and not cell.border_bottom
            ):
                cell.merge_down()

        # In these columns, we want to split rows at larger vertical gaps.
        splitcols = range(8, 14)
        row = 2
        while row < table.num_rows:
            # Collect the vertical positions of text and the gaps in between
            intv = FloatIntervals(eps=4.5)
            for cell in table[row, splitcols]:
                for element in cell:
                    if isinstance(element, LTChar):
                        intv.add(element.y0, element.y1)
            # For each such gap, split the columns in the middle of the gap
            for line2, line1 in pairwise(intv):
                table.split_row((line1[1] + line2[0]) * 0.5, splitcols)
                row += 1
            row += 1

    def test_table1(self):
        """ Test that the table in table1.pdf is detected correctly """

        laparams = LAParams(
            detect_vertical=True,
            table_border_maxwidth=1.2,
            table_postprocess=self.table1_postproc,
        )
        page: LTPage = next(
            extract_pages(
                absolute_sample_path("table1.pdf"),
                page_numbers=(0,),
                laparams=laparams,
            )
        )
        text = ""
        table: Optional[LTTable] = None
        for element in page:
            if isinstance(element, LTTextBox):
                text += element.get_text()
            elif isinstance(element, LTTable):
                table = element
            elif isinstance(element, LTLine):
                pass
            else:
                pytest.fail(f"Unexpected element: {element}")

        assert text == "Some text outside the table\n"
        assert table is not None
        check_table(table)
        assert table.num_cols == 14 and table.num_rows == 6
        assert len(table) == 1 + 5 + 13 + 2 * 8 + 4 * 6
        for cell in table:
            assert (
                cell.get_text()
                == f"c{cell.col}+{cell.colspan}\nr{cell.row}+{cell.rowspan}"
            )
