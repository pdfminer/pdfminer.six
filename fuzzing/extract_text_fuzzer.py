import sys

import atheris

from fuzzing.fuzzed_data_provider import PdfminerFuzzedDataProvider

with atheris.instrument_imports():
    from fuzzing.utils import (
        prepare_pdfminer_fuzzing,
        is_valid_byte_stream,
        generate_layout_parameters,
        should_ignore_error,
    )
    from pdfminer.high_level import extract_text

from pdfminer.psparser import PSException


def fuzz_one_input(data: bytes) -> None:
    if not is_valid_byte_stream(data):
        # Not worth continuing with this test case
        return

    fdp = PdfminerFuzzedDataProvider(data)

    try:
        extract_text(
            fdp.ConsumeMemoryFile(),
            maxpages=fdp.ConsumeIntInRange(0, 10),
            page_numbers=fdp.ConsumeOptionalIntList(10, 0, 10),
            laparams=generate_layout_parameters(fdp),
        )
    except (AssertionError, PSException):
        return
    except Exception as e:
        if should_ignore_error(e):
            return
        raise e


if __name__ == "__main__":
    prepare_pdfminer_fuzzing()
    atheris.Setup(sys.argv, fuzz_one_input)
    atheris.Fuzz()
