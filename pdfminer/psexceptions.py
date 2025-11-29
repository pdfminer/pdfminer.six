__all__ = [
    "PSException",
    "PSEOF",
    "PSSyntaxError",
    "PSTypeError",
    "PSValueError",
]


class PSException(Exception):
    """Base class for PostScript-related exceptions."""


class PSEOF(PSException):
    """Raised when an unexpected end-of-file is encountered."""


class PSSyntaxError(PSException):
    """Raised when a PostScript syntax error occurs."""


class PSTypeError(PSException):
    """Raised when an unexpected operand type is encountered."""


class PSValueError(PSException):
    """Raised when a PostScript value is invalid or out of range."""
