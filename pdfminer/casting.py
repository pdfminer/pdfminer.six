import itertools
from typing import Any

from pdfminer.utils import Matrix, Rect

_FloatTriple = tuple[float, float, float]
_FloatQuadruple = tuple[float, float, float, float]


def safe_int(o: Any) -> int | None:
    try:
        return int(o)
    except (TypeError, ValueError):
        return None


def safe_float(o: Any) -> float | None:
    try:
        return float(o)
    except (TypeError, ValueError, OverflowError):
        return None


def safe_matrix(a: Any, b: Any, c: Any, d: Any, e: Any, f: Any) -> Matrix | None:
    a_f = safe_float(a)
    b_f = safe_float(b)
    c_f = safe_float(c)
    d_f = safe_float(d)
    e_f = safe_float(e)
    f_f = safe_float(f)

    if (
        a_f is None
        or b_f is None
        or c_f is None
        or d_f is None
        or e_f is None
        or f_f is None
    ):
        return None

    return a_f, b_f, c_f, d_f, e_f, f_f


def safe_rgb(r: Any, g: Any, b: Any) -> tuple[float, float, float] | None:
    return _safe_float_triple(r, g, b)


def safe_cmyk(
    c: Any, m: Any, y: Any, k: Any
) -> tuple[float, float, float, float] | None:
    return _safe_float_quadruple(c, m, y, k)


def safe_rect_list(value: Any) -> Rect | None:
    try:
        values = list(itertools.islice(value, 4))
    except TypeError:
        return None

    if len(values) != 4:
        return None

    return safe_rect(*values)


def safe_rect(a: Any, b: Any, c: Any, d: Any) -> Rect | None:
    return _safe_float_quadruple(a, b, c, d)


def _safe_float_triple(a: Any, b: Any, c: Any) -> _FloatTriple | None:
    a_f = safe_float(a)
    b_f = safe_float(b)
    c_f = safe_float(c)

    if a_f is None or b_f is None or c_f is None:
        return None

    return a_f, b_f, c_f


def _safe_float_quadruple(a: Any, b: Any, c: Any, d: Any) -> _FloatQuadruple | None:
    a_f = safe_float(a)
    b_f = safe_float(b)
    c_f = safe_float(c)
    d_f = safe_float(d)

    if a_f is None or b_f is None or c_f is None or d_f is None:
        return None

    return a_f, b_f, c_f, d_f
