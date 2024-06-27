import sys

import atheris

from fuzzing.fuzz_helpers import EnhancedFuzzedDataProvider

with atheris.instrument_imports():
    from fuzzing.pdf_utils import PDFValidator, prepare_pdfminer_fuzzing
    from pdfminer.high_level import extract_text

from pdfminer.psparser import PSException


def fuzz_one_input(data: bytes) -> None:
    if not PDFValidator.is_valid_byte_stream(data):
        # Not worth continuing with this test case
        return

    fdp = EnhancedFuzzedDataProvider(data)

    try:
        extract_text(
            fdp.ConsumeMemoryFile(),
            maxpages=fdp.ConsumeIntInRange(0, 10),
            page_numbers=fdp.ConsumeOptionalIntList(10, 0, 10),
            laparams=PDFValidator.generate_layout_parameters(fdp),
        )
    except (AssertionError, PSException):
        return
    except Exception as e:
        if PDFValidator.should_ignore_error(e):
            return
        raise e


if __name__ == "__main__":
    prepare_pdfminer_fuzzing()
    atheris.Setup(sys.argv, fuzz_one_input)
    atheris.Fuzz()
