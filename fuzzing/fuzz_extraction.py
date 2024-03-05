import atheris
import sys

from io import BytesIO
from fuzz_helpers import EnhancedFuzzedDataProvider

from pdfminer.pdfdocument import PDFNoValidXRef
from pdfminer.pdfparser import PDFException
from pdfminer.psparser import PSException

with atheris.instrument_imports():
    from pdfminer.high_level import extract_text, extract_pages, extract_text_to_fp


output_types = [
    'text',
    'html',
    'xml',
    'tag'
]

# TODO: Investigate protobuf for structure-aware fuzzing of PDFs
# TODO: If not protobuf, CustomMutator
def TestOneInput(data: bytes):
    fdp = EnhancedFuzzedDataProvider(data)

    extraction_type = fdp.ConsumeIntInRange(0, 2)

    try:
        if extraction_type == 0:
            with fdp.ConsumeMemoryFile() as f:
                extract_text(
                    f,
                    page_numbers=fdp.ConsumeIntList(5, 4),
                )
        elif extraction_type == 1:
            with fdp.ConsumeMemoryFile() as f:
                extract_pages(f)
        else:
            out = BytesIO()
            out_type = fdp.PickValueInList(output_types)
            scale = fdp.ConsumeFloatInRange(0.0, 2.0)
            rotation = fdp.ConsumeIntInRange(0, 360)
            strip_control = fdp.ConsumeBool()

            with fdp.ConsumeMemoryFile() as f:
                extract_text_to_fp(
                    f,
                    out,
                    codec='utf-8',
                    output_type=out_type,
                    scale=scale,
                    rotation=rotation,
                    strip_control=strip_control
               )
    except (PDFException, PDFNoValidXRef, PSException) as e:
        return -1



def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()

