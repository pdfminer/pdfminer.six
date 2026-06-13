"""Number and string formatting utilities for PDF output.

Provides formatting functions for Roman numerals, alphabetic labels,
bounding box strings, matrix strings, and XML-safe encoding.
"""

import string
from html import escape

from pdfminer.geometry.matrix import Matrix, Rect


# ─── Number formatters ─────────────────────────────────────────────────────

ROMAN_ONES = ["i", "x", "c", "m"]
ROMAN_FIVES = ["v", "l", "d"]


def format_int_roman(value: int) -> str:
    """Format a positive integer as lowercase Roman numerals.

    Supports values from 1 to 3999 (standard Roman numeral range).

    :param value: A positive integer (1 <= value < 4000).
    :returns: The Roman numeral representation.
    :raises AssertionError: If value is out of range.
    """
    assert 0 < value < 4000
    result: list[str] = []
    index = 0

    while value != 0:
        value, remainder = divmod(value, 10)
        if remainder == 9:
            result.insert(0, ROMAN_ONES[index])
            result.insert(1, ROMAN_ONES[index + 1])
        elif remainder == 4:
            result.insert(0, ROMAN_ONES[index])
            result.insert(1, ROMAN_FIVES[index])
        else:
            over_five = remainder >= 5
            if over_five:
                result.insert(0, ROMAN_FIVES[index])
                remainder -= 5
            result.insert(1 if over_five else 0, ROMAN_ONES[index] * remainder)
        index += 1

    return "".join(result)


def format_int_alpha(value: int) -> str:
    """Format a positive integer as lowercase alphabetic labels.

    Produces: a, b, c, ..., z, aa, ab, ..., zz, aaa, ...
    Used for PDF list numbering and page labels.

    :param value: A positive integer (value >= 1).
    :returns: The alphabetic label string.
    :raises AssertionError: If value is not positive.
    """
    assert value > 0
    result: list[str] = []

    while value != 0:
        value, remainder = divmod(value - 1, len(string.ascii_lowercase))
        result.append(string.ascii_lowercase[remainder])

    result.reverse()
    return "".join(result)


# ─── PDF geometry formatters ───────────────────────────────────────────────

def bbox2str(bbox: Rect) -> str:
    """Format a bounding box as a comma-separated string with 3 decimal places.

    :param bbox: A rectangle (x0, y0, x1, y1).
    :returns: A formatted string like "0.000,0.000,612.000,792.000".
    """
    (x0, y0, x1, y1) = bbox
    return f"{x0:.3f},{y0:.3f},{x1:.3f},{y1:.3f}"


def matrix2str(m: Matrix) -> str:
    """Format a transformation matrix as a readable string.

    :param m: A 6-element matrix (a, b, c, d, e, f).
    :returns: A formatted string like "[1.00,0.00,0.00,1.00, (0.00,0.00)]".
    """
    (a, b, c, d, e, f) = m
    return f"[{a:.2f},{b:.2f},{c:.2f},{d:.2f}, ({e:.2f},{f:.2f})]"


# ─── XML/HTML encoding ─────────────────────────────────────────────────────

def enc(x: str) -> str:
    """Encode a string for safe inclusion in SGML/XML/HTML output.

    Uses HTML entity escaping for special characters like <, >, &, ".
    Returns an empty string for bytes input (which should not appear
    in text output).

    .. deprecated::
        Use :func:`encode_xml_safe` for clearer naming.

    :param x: The string to encode.
    :returns: The HTML-escaped string.
    """
    if isinstance(x, bytes):
        return ""
    return escape(x)


def encode_xml_safe(x: str) -> str:
    """Encode a string for safe inclusion in SGML/XML/HTML output.

    This is the renamed version of :func:`enc` with a self-explanatory
    name. Uses HTML entity escaping for special characters.

    :param x: The string to encode.
    :returns: The HTML-escaped string.
    """
    if isinstance(x, bytes):
        return ""
    return escape(x)
