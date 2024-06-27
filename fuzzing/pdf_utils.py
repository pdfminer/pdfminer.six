"""
Utilities shared across the various PDF fuzzing harnesses
"""
import logging
from typing import Optional

import atheris

from pdfminer.layout import LAParams
from pdfminer.psparser import PSException

# List of all exception message substrings explicitly raised by pdfminer that do not inherit from PSException
_EXPLICIT_EXCEPTION_MESSAGES = [
    "Unsupported",
    "duplicate labels",
    "AcroForm",
    "SASLPrep",
    "Invalid",
]


def prepare_pdfminer_fuzzing():
    """
    Used to disable logging of the pdfminer module
    """
    logging.getLogger("pdfminer").setLevel(logging.CRITICAL)


class PDFValidator:
    """
    Custom mutator class for PDFs for more efficient fuzzing
    """

    _PDF_MAGIC_BYTES = b"%PDF-"

    @staticmethod
    @atheris.instrument_func
    def is_valid_byte_stream(data: bytes) -> bool:
        """
        Performs basic checks on the incoming byte-stream to determine if it is worth passing the input to the library
        :return: Whether the byte-stream passes the basic checks
        """
        if not data.startswith(PDFValidator._PDF_MAGIC_BYTES):
            return False
        if b"/Root" not in data:
            return False

        return True

    @staticmethod
    @atheris.instrument_func
    def generate_layout_parameters(
        fdp: atheris.FuzzedDataProvider,
    ) -> Optional[LAParams]:
        return (
            LAParams(
                line_overlap=fdp.ConsumeFloat(),
                char_margin=fdp.ConsumeFloat(),
                line_margin=fdp.ConsumeFloat(),
                word_margin=fdp.ConsumeFloat(),
                boxes_flow=fdp.ConsumeFloatInRange(-1.0, 1.0)
                if fdp.ConsumeBool()
                else None,
                detect_vertical=fdp.ConsumeBool(),
                all_texts=fdp.ConsumeBool(),
            )
            if fdp.ConsumeBool()
            else None
        )

    @staticmethod
    def should_ignore_error(e: Exception) -> bool:
        """
        Determines if the given raised exception is an exception explicitly raised by pdfminer
        :param e: The exception to check
        :return: Whether the exception should be ignored or re-thrown
        """
        return isinstance(e, PSException) or any(
            em_ss in str(e) for em_ss in _EXPLICIT_EXCEPTION_MESSAGES
        )
