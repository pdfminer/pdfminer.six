from typing import Any, Optional, Tuple

from pdfminer.utils import Matrix


def safe_int(o: Any) -> Optional[int]:
    try:
        return int(o)
    except (TypeError, ValueError):
        return None


def safe_float(o: Any) -> Optional[float]:
    try:
        return float(o)
    except (TypeError, ValueError):
        return None


def safe_matrix(a: Any, b: Any, c: Any, d: Any, e: Any, f: Any) -> Optional[Matrix]:
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


def safe_rgb(r: Any, g: Any, b: Any) -> Optional[Tuple[float, float, float]]:
    r_f = safe_float(r)
    g_f = safe_float(g)
    b_f = safe_float(b)

    if r_f is None or g_f is None or b_f is None:
        return None

    return r_f, g_f, b_f


def safe_cmyk(
    c: Any, m: Any, y: Any, k: Any
) -> Optional[Tuple[float, float, float, float]]:
    c_f = safe_float(c)
    m_f = safe_float(m)
    y_f = safe_float(y)
    k_f = safe_float(k)

    if c_f is None or m_f is None or y_f is None or k_f is None:
        return None

    return (c_f, m_f, y_f, k_f)
