"""
Utilities shared across the various PDF fuzzing harnesses
"""
import logging
from typing import Optional

import atheris

from pdfminer.layout import LAParams
from pdfminer.psparser import PSException

PDF_MAGIC_BYTES = b"%PDF-"

# List of all exception message substrings explicitly raised by pdfminer that do not
# inherit from PSException
_EXPLICIT_EXCEPTION_MESSAGES = [
    "Unsupported",
    "duplicate labels",
    "AcroForm",
    "SASLPrep",
    "Invalid",
]


def prepare_pdfminer_fuzzing() -> None:
    """
    Used to disable logging of the pdfminer module
    """
    logging.getLogger("pdfminer").setLevel(logging.CRITICAL)


def should_ignore_error(e: Exception) -> bool:
    """
    Determines if the given raised exception is explicitly raised by pdfminer
    :param e: The exception to check
    :return: Whether the exception should be ignored or re-thrown
    """
    return isinstance(e, PSException) or any(
        em_ss in str(e) for em_ss in _EXPLICIT_EXCEPTION_MESSAGES
    )


@atheris.instrument_func  # type: ignore[misc]
def generate_layout_parameters(
    fdp: atheris.FuzzedDataProvider,
) -> Optional[LAParams]:
    if fdp.ConsumeBool():
        return None

    boxes_flow: Optional[float] = None
    if fdp.ConsumeBool():
        boxes_flow = fdp.ConsumeFloatInRange(-1.0, 1.0)

    return LAParams(
        line_overlap=fdp.ConsumeFloat(),
        char_margin=fdp.ConsumeFloat(),
        line_margin=fdp.ConsumeFloat(),
        word_margin=fdp.ConsumeFloat(),
        boxes_flow=boxes_flow,
        detect_vertical=fdp.ConsumeBool(),
        all_texts=fdp.ConsumeBool(),
    )


@atheris.instrument_func  # type: ignore[misc]
def is_valid_byte_stream(data: bytes) -> bool:
    """Quick check to see if this is worth of passing to atheris
    :return: Whether the byte-stream passes the basic checks
    """
    if not data.startswith(PDF_MAGIC_BYTES):
        return False
    if b"/Root" not in data:
        return False

    return True
