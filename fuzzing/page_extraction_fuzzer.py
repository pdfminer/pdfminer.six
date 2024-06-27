#!/usr/bin/env python3
import atheris
import sys

from fuzz_helpers import EnhancedFuzzedDataProvider

with atheris.instrument_imports():
    from pdf_utils import PDFValidator, prepare_pdfminer_fuzzing
    from pdfminer.high_level import extract_pages
    from pdfminer.psparser import PSException


def test_one_input(data: bytes) -> None:
    if not PDFValidator.is_valid_byte_stream(data):
        # Not worth continuing with this test case
        return

    fdp = EnhancedFuzzedDataProvider(data)

    try:
        with fdp.ConsumeMemoryFile() as f:
            max_pages = fdp.ConsumeIntInRange(0, 1000)
            list(
                extract_pages(
                    f,
                    maxpages=max_pages,
                    page_numbers=fdp.ConsumeIntList(
                        fdp.ConsumeIntInRange(0, max_pages), 2
                    ),
                    laparams=PDFValidator.generate_layout_parameters(fdp),
                )
            )
    except (AssertionError, PSException):
        return
    except Exception as e:
        if PDFValidator.should_ignore_error(e):
            return
        raise e


if __name__ == "__main__":
    prepare_pdfminer_fuzzing()
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()
