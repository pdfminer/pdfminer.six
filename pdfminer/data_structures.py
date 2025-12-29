import itertools
from collections.abc import Iterable
from typing import Any

from pdfminer import settings
from pdfminer.pdfparser import PDFSyntaxError
from pdfminer.pdftypes import dict_value, int_value, list_value
from pdfminer.utils import choplist


class NumberTree:
    """A PDF number tree.

    See Section 3.8.6 of the PDF Reference.
    """

    def __init__(self, obj: Any):
        self._obj = dict_value(obj)
        self.nums: Iterable[Any] | None = None
        self.kids: Iterable[Any] | None = None
        self.limits: Iterable[Any] | None = None

        if "Nums" in self._obj:
            self.nums = list_value(self._obj["Nums"])
        if "Kids" in self._obj:
            self.kids = list_value(self._obj["Kids"])
        if "Limits" in self._obj:
            self.limits = list_value(self._obj["Limits"])

    def _parse(self) -> list[tuple[int, Any]]:
        items = []
        if self.nums:  # Leaf node
            for k, v in choplist(2, self.nums):
                items.append((int_value(k), v))

        if self.kids:  # Root or intermediate node
            for child_ref in self.kids:
                items += NumberTree(child_ref)._parse()

        return items

    values: list[tuple[int, Any]]  # workaround decorators unsupported by mypy

    @property  # type: ignore[no-redef,misc]
    def values(self) -> list[tuple[int, Any]]:
        values = self._parse()

        if settings.STRICT:
            if not all(a[0] <= b[0] for a, b in itertools.pairwise(values)):
                raise PDFSyntaxError("Number tree elements are out of order")
        else:
            values.sort(key=lambda t: t[0])

        return values
