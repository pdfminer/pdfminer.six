#!/usr/bin/env python3
import sys

import atheris

from fuzzing.fuzzed_data_provider import PdfminerFuzzedDataProvider

with atheris.instrument_imports():
    from fuzzing.utils import (
        generate_layout_parameters,
        is_valid_byte_stream,
        prepare_pdfminer_fuzzing,
    )
    from pdfminer.high_level import extract_pages
    from pdfminer.psexceptions import PSException


def fuzz_one_input(data: bytes) -> None:
    if not is_valid_byte_stream(data):
        # Not worth continuing with this test case
        return

    fdp = PdfminerFuzzedDataProvider(data)

    try:
        with fdp.ConsumeMemoryFile() as f:
            list(
                extract_pages(
                    f,
                    maxpages=fdp.ConsumeIntInRange(0, 10),
                    page_numbers=fdp.ConsumeOptionalIntList(10, 0, 10),
                    laparams=generate_layout_parameters(fdp),
                )
            )
    except (AssertionError, PSException):
        return


if __name__ == "__main__":
    prepare_pdfminer_fuzzing()
    atheris.Setup(sys.argv, fuzz_one_input)
    atheris.Fuzz()
