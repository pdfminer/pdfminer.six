"""Utilities shared across the various PDF fuzzing harnesses"""

import logging

import atheris

from pdfminer.layout import LAParams

PDF_MAGIC_BYTES = b"%PDF-"


def prepare_pdfminer_fuzzing() -> None:
    """Used to disable logging of the pdfminer module"""
    logging.getLogger("pdfminer").setLevel(logging.CRITICAL)


@atheris.instrument_func  # type: ignore[misc]
def generate_layout_parameters(
    fdp: atheris.FuzzedDataProvider,
) -> LAParams | None:
    if fdp.ConsumeBool():
        return None

    boxes_flow: float | None = None
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
