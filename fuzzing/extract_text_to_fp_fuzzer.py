import io
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
    from pdfminer.high_level import extract_text_to_fp
    from pdfminer.psparser import PSException

available_output_formats = ["text", "html", "xml", "tag"]
available_layout_modes = ["exact", "normal", "loose"]


def fuzz_one_input(data: bytes) -> None:
    if not is_valid_byte_stream(data):
        # Not worth continuing with this test case
        return

    fdp = PdfminerFuzzedDataProvider(data)

    try:
        with fdp.ConsumeMemoryFile(all_data=False) as f_in, io.BytesIO() as f_out:
            extract_text_to_fp(
                f_in,
                f_out,
                output_type=fdp.PickValueInList(available_output_formats),
                laparams=generate_layout_parameters(fdp),
                maxpages=fdp.ConsumeIntInRange(0, 10),
                page_numbers=fdp.ConsumeOptionalIntList(10, 0, 10),
                scale=fdp.ConsumeFloatInRange(0.0, 2.0),
                rotation=fdp.ConsumeIntInRange(0, 360),
                layoutmode=fdp.PickValueInList(available_layout_modes),
                strip_control=fdp.ConsumeBool(),
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
