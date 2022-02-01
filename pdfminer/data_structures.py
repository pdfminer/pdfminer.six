import functools
from typing import Tuple, Any, List, Optional

from pdfminer import settings
from pdfminer.pdfparser import PDFSyntaxError
from pdfminer.pdftypes import list_value, int_value, dict_value
from pdfminer.utils import choplist


class NumberTree:
    """A PDF number tree.

    See Section 3.8.6 of the PDF Reference.
    """
    def __init__(self, obj: Any):
        self._obj = dict_value(obj)
        self.nums: Optional[List[Any]] = None
        self.kids: Optional[List[int]] = None
        self.limits: Optional[List[int]] = None

        if 'Nums' in self._obj:
            self.nums = list_value(self._obj['Nums'])
        if 'Kids' in self._obj:
            self.kids = list_value(self._obj['Kids'])
        if 'Limits' in self._obj:
            self.limits = list_value(self._obj['Limits'])

    def _parse(self) -> List[Tuple[int, Any]]:
        l = []
        if self.nums:  # Leaf node
            for k, v in choplist(2, self.nums):
                l.append((int_value(k), dict_value(v)))

        if self.kids:  # Root or intermediate node
            for child_ref in self.kids:
                for k, v in NumberTree(child_ref).values:
                    l.append(([k], v))

        return l

    @property
    @functools.lru_cache
    def values(self) -> List[Tuple[int, Any]]:
        values = self._parse()

        if settings.STRICT:
            if not all(a[0] <= b[0] for a, b in zip(values, values[1:])):
                raise PDFSyntaxError('PageLabels are out of order')
        else:
            values.sort(key=lambda t: t[0])

        return values
