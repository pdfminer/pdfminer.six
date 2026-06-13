"""2D affine matrix and geometric operations for PDF coordinate transforms.

This module contains pure functions for matrix multiplication, point/rectangle
transformation, and geometric calculations used throughout pdfminer for
coordinate system transformations.
"""

from pdfminer.geometry.matrix import (
    MATRIX_IDENTITY,
    Matrix,
    Point,
    Rect,
    apply_matrix_norm,
    apply_matrix_pt,
    apply_matrix_rect,
    mult_matrix,
    parse_rect,
    translate_matrix,
)
from pdfminer.geometry.spatial import get_bound, vecBetweenBoxes

__all__ = [
    "MATRIX_IDENTITY",
    "Matrix",
    "Point",
    "Rect",
    "apply_matrix_norm",
    "apply_matrix_pt",
    "apply_matrix_rect",
    "get_bound",
    "mult_matrix",
    "parse_rect",
    "translate_matrix",
    "vecBetweenBoxes",
]
