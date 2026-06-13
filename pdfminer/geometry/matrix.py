"""2D affine matrix operations for PDF coordinate transformations.

PDF uses 2D affine transformations represented as 6-element tuples:
  (a, b, c, d, e, f)

The transformation maps a point (x, y) to:
  (a*x + c*y + e, b*x + d*y + f)

This is equivalent to the matrix:
  | a  c  e |
  | b  d  f |
  | 0  0  1 |

Reference: PDF Reference 1.7, Section 4.2.2 — Coordinate Systems.
"""

from typing import Any, Union

from pdfminer.pdfexceptions import PDFValueError

# ─── Type aliases ────────────────────────────────────────────────────────────

Point = tuple[float, float]
Rect = tuple[float, float, float, float]
Matrix = tuple[float, float, float, float, float, float]
PathSegment = Union[
    tuple[str],  # Literal['h']
    tuple[str, float, float],  # Literal['m', 'l']
    tuple[str, float, float, float, float],  # Literal['v', 'y']
    tuple[str, float, float, float, float, float, float],
]  # Literal['c']

# ─── Constants ───────────────────────────────────────────────────────────────

MATRIX_IDENTITY: Matrix = (1, 0, 0, 1, 0, 0)


# ─── Parsing ────────────────────────────────────────────────────────────────

def parse_rect(o: Any) -> Rect:
    """Parse a sequence of 4 numbers into a rectangle tuple.

    :param o: An iterable of 4 numeric values (x0, y0, x1, y1).
    :returns: A Rect tuple of 4 floats.
    :raises PDFValueError: If the input cannot be unpacked into 4 values.
    """
    try:
        (x0, y0, x1, y1) = o
        return float(x0), float(y0), float(x1), float(y1)
    except ValueError as err:
        raise PDFValueError("Could not parse rectangle") from err


# ─── Matrix arithmetic ─────────────────────────────────────────────────────

def mult_matrix(m1: Matrix, m0: Matrix) -> Matrix:
    """Multiply two 2D affine transformation matrices.

    Computes m1 * m0, where m1 is applied first in the transformation
    pipeline. The result represents the composition of both transforms.

    :param m1: The first (inner) matrix — applied first.
    :param m0: The second (outer) matrix — applied second.
    :returns: The composed transformation matrix.
    """
    (a1, b1, c1, d1, e1, f1) = m1
    (a0, b0, c0, d0, e0, f0) = m0
    return (
        a0 * a1 + c0 * b1,
        b0 * a1 + d0 * b1,
        a0 * c1 + c0 * d1,
        b0 * c1 + d0 * d1,
        a0 * e1 + c0 * f1 + e0,
        b0 * e1 + d0 * f1 + f0,
    )


def translate_matrix(m: Matrix, v: Point) -> Matrix:
    """Translate a matrix's origin to a new position within its coordinate system.

    The matrix is changed so that its origin is at the specified point in its own
    coordinate system. Note that this is different from translating it within the
    original coordinate system.

    :param m: The transformation matrix to translate.
    :param v: The (x, y) point to translate to.
    :returns: A new matrix with the translation applied.
    """
    (a, b, c, d, e, f) = m
    (x, y) = v
    return a, b, c, d, x * a + y * c + e, x * b + y * d + f


# ─── Point/rect transforms ─────────────────────────────────────────────────

def apply_matrix_pt(m: Matrix, v: Point) -> Point:
    """Apply an affine transformation matrix to a 2D point.

    Maps (x, y) to (a*x + c*y + e, b*x + d*y + f).

    :param m: The transformation matrix (a, b, c, d, e, f).
    :param v: The point (x, y) to transform.
    :returns: The transformed point.
    """
    (a, b, c, d, e, f) = m
    (x, y) = v
    return a * x + c * y + e, b * x + d * y + f


def apply_matrix_rect(m: Matrix, rect: Rect) -> Rect:
    """Apply an affine transformation matrix to a rectangle.

    Transforms all four corners of the rectangle and returns the
    axis-aligned bounding rectangle that tightly fits the transformed
    result. Note that the result is not a rotated rectangle, but a
    rectangle with the same orientation that tightly fits the outside
    of the rotated content.

    :param m: The transformation matrix.
    :param rect: The rectangle (x0, y0, x1, y1), where x0 < x1 and y0 < y1.
    :returns: An axis-aligned bounding rectangle for the transformed content.
    """
    (x0, y0, x1, y1) = rect
    left_bottom = (x0, y0)
    right_bottom = (x1, y0)
    right_top = (x1, y1)
    left_top = (x0, y1)

    (left1, bottom1) = apply_matrix_pt(m, left_bottom)
    (right1, bottom2) = apply_matrix_pt(m, right_bottom)
    (right2, top1) = apply_matrix_pt(m, right_top)
    (left2, top2) = apply_matrix_pt(m, left_top)

    return (
        min(left1, left2, right1, right2),
        min(bottom1, bottom2, top1, top2),
        max(left1, left2, right1, right2),
        max(bottom1, bottom2, top1, top2),
    )


def apply_matrix_norm(m: Matrix, v: Point) -> Point:
    """Apply a transformation matrix to a direction vector (normal).

    Equivalent to apply_matrix_pt(m, (p, q)) - apply_matrix_pt(m, (0, 0)),
    which removes the translation component and only applies the
    rotation/scaling part. Used for transforming direction vectors
    that should not be affected by translation.

    :param m: The transformation matrix.
    :param v: The direction vector (p, q).
    :returns: The transformed direction vector.
    """
    (a, b, c, d, _e, _f) = m
    (p, q) = v
    return a * p + c * q, b * p + d * q
