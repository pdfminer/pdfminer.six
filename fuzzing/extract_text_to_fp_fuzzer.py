import io
import sys

import atheris

from fuzz_helpers import EnhancedFuzzedDataProvider

with atheris.instrument_imports():
    from pdf_utils import PDFValidator, prepare_pdfminer_fuzzing
    from pdfminer.high_level import extract_text_to_fp
    from pdfminer.psparser import PSException

available_output_formats = [
    'text',
    'html',
    'xml',
    'tag'
]
available_layout_modes = [
    'exact',
    'normal',
    'loose'
]


def TestOneInput(data: bytes):
    if not PDFValidator.is_valid_byte_stream(data):
        # Not worth continuing with this test case
        return -1

    fdp = EnhancedFuzzedDataProvider(data)

    try:
        with fdp.ConsumeMemoryFile(all_data=False) as f_in, io.BytesIO() as f_out:
            max_pages = fdp.ConsumeIntInRange(0, 1000)
            extract_text_to_fp(
                f_in,
                f_out,
                output_type=fdp.PickValueInList(available_output_formats),
                laparams=PDFValidator.generate_layout_parameters(fdp),
                maxpages=max_pages,
                page_numbers=fdp.ConsumeIntList(fdp.ConsumeIntInRange(0, max_pages), 2),
                scale=fdp.ConsumeFloatInRange(0.0, 2.0),
                rotation=fdp.ConsumeIntInRange(0, 360),
                layoutmode=fdp.PickValueInList(available_layout_modes),
                strip_control=fdp.ConsumeBool()
            )
    except (AssertionError, PSException):
        return -1
    except Exception as e:
        if PDFValidator.should_ignore_error(e):
            return -1
        raise e


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    prepare_pdfminer_fuzzing()
    main()
