"""Miscellaneous Routines.

This module provides backward-compatible imports for all utility functions.
Domain-specific logic has been extracted into submodules:

- ``pdfminer.geometry.matrix`` — 2D affine matrix operations
- ``pdfminer.geometry.spatial`` — Bounding boxes, distances, Plane index
- ``pdfminer.prediction`` — PNG/TIFF predictor filters
- ``pdfminer.textencoding`` — PDF text encoding/decoding
- ``pdfminer.formatting`` — Number and string formatting utilities
"""

import io
import pathlib
import string
from collections.abc import Callable, Iterable, Iterator
from html import escape
from typing import (
    TYPE_CHECKING,
    Any,
    BinaryIO,
    Generic,
    TextIO,
    TypeVar,
    Union,
    cast,
)

from pdfminer.pdfexceptions import PDFTypeError, PDFValueError

if TYPE_CHECKING:
    from pdfminer.layout import LTComponent

import contextlib

import charset_normalizer  # For str encoding detection

# from sys import maxint as INF doesn't work anymore under Python3, but PDF
# still uses 32 bits ints
INF = (1 << 31) - 1

FileOrName = Union[pathlib.PurePath, str, io.IOBase]
AnyIO = Union[TextIO, BinaryIO]


class open_filename:
    """Context manager that allows opening a filename
    (str or pathlib.PurePath type is supported) and closes it on exit,
    (just like `open`), but does nothing for file-like objects.
    """

    def __init__(self, filename: FileOrName, *args: Any, **kwargs: Any) -> None:
        if isinstance(filename, pathlib.PurePath):
            filename = str(filename)
        if isinstance(filename, str):
            self.file_handler: AnyIO = open(filename, *args, **kwargs)  # noqa: SIM115
            self.closing = True
        elif isinstance(filename, io.IOBase):
            self.file_handler = cast(AnyIO, filename)
            self.closing = False
        else:
            raise PDFTypeError(f"Unsupported input type: {type(filename)}")

    def __enter__(self) -> AnyIO:
        return self.file_handler

    def __exit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        if self.closing:
            self.file_handler.close()


def make_compat_bytes(in_str: str) -> bytes:
    """Converts to bytes, encoding to unicode."""
    assert isinstance(in_str, str), str(type(in_str))
    return in_str.encode()


def make_compat_str(o: object) -> str:
    """Converts everything to string, if bytes guessing the encoding."""
    if isinstance(o, bytes):
        enc = charset_normalizer.detect(o)
        if enc["encoding"] is None:
            return str(o)
        try:
            return o.decode(enc["encoding"])
        except UnicodeDecodeError:
            return str(o)
    else:
        return str(o)


def shorten_str(s: str, size: int) -> str:
    if size < 7:
        return s[:size]
    if len(s) > size:
        length = (size - 5) // 2
        return f"{s[:length]} ... {s[-length:]}"
    else:
        return s


def compatible_encode_method(
    bytesorstring: bytes | str,
    encoding: str = "utf-8",
    erraction: str = "ignore",
) -> str:
    """When Py2 str.encode is called, it often means bytes.encode in Py3.

    This does either.
    """
    if isinstance(bytesorstring, str):
        return bytesorstring
    assert isinstance(bytesorstring, bytes), str(type(bytesorstring))
    return bytesorstring.decode(encoding, erraction)


# ─── Re-export from prediction submodule ───────────────────────────────────
from pdfminer.prediction import (  # noqa: E402
    apply_png_predictor,
    apply_tiff_predictor,
    paeth_predictor,
)

# ─── Re-export from geometry submodule ─────────────────────────────────────
from pdfminer.geometry.matrix import (  # noqa: E402
    MATRIX_IDENTITY,
    Matrix,
    PathSegment,
    Point,
    Rect,
    apply_matrix_norm,
    apply_matrix_pt,
    apply_matrix_rect,
    mult_matrix,
    parse_rect,
    translate_matrix,
)

from pdfminer.geometry.spatial import (  # noqa: E402
    Plane,
    LTComponentT,
    get_bound,
    vecBetweenBoxes,
)

# ─── Re-export from formatting submodule ───────────────────────────────────
from pdfminer.formatting import (  # noqa: E402
    bbox2str,
    enc,
    encode_xml_safe,
    format_int_alpha,
    format_int_roman,
    matrix2str,
)

# ─── Re-export from textencoding submodule ─────────────────────────────────
from pdfminer.textencoding import (  # noqa: E402
    PDFDocEncoding,
    decode_text,
    unpad_aes,
)


#  Utility functions


def isnumber(x: object) -> bool:
    return isinstance(x, (int, float))


_T = TypeVar("_T")


def uniq(objs: Iterable[_T]) -> Iterator[_T]:
    """Eliminates duplicated elements."""
    done = set()
    for obj in objs:
        if obj in done:
            continue
        done.add(obj)
        yield obj


def fsplit(pred: Callable[[_T], bool], objs: Iterable[_T]) -> tuple[list[_T], list[_T]]:
    """Split a list into two classes according to the predicate."""
    t = []
    f = []
    for obj in objs:
        if pred(obj):
            t.append(obj)
        else:
            f.append(obj)
    return t, f


def drange(v0: float, v1: float, d: int) -> range:
    """Returns a discrete range."""
    return range(int(v0) // d, int(v1 + d) // d)


def pick(
    seq: Iterable[_T],
    func: Callable[[_T], float],
    maxobj: _T | None = None,
) -> _T | None:
    """Picks the object obj where func(obj) has the highest value.

    Renamed from the vague name ``pick`` to clarify intent: this selects
    the element that maximizes the given scoring function.

    :param seq: An iterable of objects to search.
    :param func: A scoring function that maps each object to a float.
    :param maxobj: An optional initial maximum object (default None).
    :returns: The object with the highest score, or None if seq is empty.
    """
    maxscore = None
    for obj in seq:
        score = func(obj)
        if maxscore is None or maxscore < score:
            (maxscore, maxobj) = (score, obj)
    return maxobj


def choplist(n: int, seq: Iterable[_T]) -> Iterator[tuple[_T, ...]]:
    """Groups every n elements of the list."""
    r = []
    for x in seq:
        r.append(x)
        if len(r) == n:
            yield tuple(r)
            r = []


def nunpack(s: bytes, default: int = 0) -> int:
    """Unpacks variable-length unsigned integers (big endian)."""
    length = len(s)
    if not length:
        return default
    else:
        return int.from_bytes(s, byteorder="big", signed=False)
