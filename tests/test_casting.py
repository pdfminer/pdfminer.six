from typing import Any, Optional

import pytest

from pdfminer.casting import safe_rect_list
from pdfminer.utils import Rect


@pytest.mark.parametrize(
    ("arg", "expected"),
    [
        ([0, 0, 0, 0], (0.0, 0.0, 0.0, 0.0)),
        ([1, 2, 3, 4], (1.0, 2.0, 3.0, 4.0)),
        ([0, 0, 0, None], None),
        ([0, 0, 0, "0"], (0.0, 0.0, 0.0, 0.0)),
        ([], None),
        ([0, 0, 0], None),
        ([1, 2, 3, 4, 5], (1.0, 2.0, 3.0, 4.0)),
        (None, None),
        (object(), None),
    ],
)
def test_safe_rect_list(arg: Any, expected: Optional[Rect]) -> None:
    assert safe_rect_list(arg) == expected
