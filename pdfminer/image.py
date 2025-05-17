import os
import os.path
from io import BytesIO
from typing import Literal, Tuple

from pdfminer.jbig2 import JBIG2StreamReader, JBIG2StreamWriter
from pdfminer.layout import LTImage
from pdfminer.pdfcolor import LITERAL_INDEXED
from pdfminer.pdfexceptions import PDFValueError
from pdfminer.pdftypes import (
    LITERALS_DCT_DECODE,
    LITERALS_JBIG2_DECODE,
    LITERALS_JPX_DECODE,
    int_value,
    stream_value,
)

PIL_ERROR_MESSAGE = (
    "Could not import Pillow. This dependency of pdfminer.six is not "
    "installed by default. You need it to to save JPEG2000 and BMP images to a file. Install it "
    "with `pip install 'pdfminer.six[image]'`"
)


class ImageWriter:
    """Write image to a file

    Supports various image types: JPEG, JBIG2 and bitmaps
    """

    def __init__(self, outdir: str) -> None:
        self.outdir = outdir
        if not os.path.exists(self.outdir):
            os.makedirs(self.outdir)

    def export_image(self, image: LTImage) -> str:
        """Save an LTImage to disk"""
        filters = image.stream.get_filters()

        if not filters:
            name = self._save_bytes(image)

        elif filters[-1][0] in LITERALS_DCT_DECODE:
            name = self._save_jpeg(image)

        elif filters[-1][0] in LITERALS_JPX_DECODE:
            name = self._save_jpeg2000(image)

        elif self._is_jbig2_iamge(image):
            name = self._save_jbig2(image)

        else:
            name = self._save_bytes(image)

        return name

    def _save_jpeg(self, image: LTImage) -> str:
        """Save a JPEG encoded image"""
        data = image.stream.get_data()

        name, path = self._create_unique_image_name(image, ".jpg")
        with open(path, "wb") as fp:
            fp.write(data)

        return name

    def _save_jpeg2000(self, image: LTImage) -> str:
        """Save a JPEG 2000 encoded image"""
        data = image.stream.get_data()

        name, path = self._create_unique_image_name(image, ".jp2")
        with open(path, "wb") as fp:
            try:
                from PIL import Image  # type: ignore[import]
            except ImportError:
                raise ImportError(PIL_ERROR_MESSAGE)

            # if we just write the raw data, most image programs
            # that I have tried cannot open the file. However,
            # open and saving with PIL produces a file that
            # seems to be easily opened by other programs
            ifp = BytesIO(data)
            i = Image.open(ifp)
            i.save(fp, "JPEG2000")
        return name

    def _save_jbig2(self, image: LTImage) -> str:
        """Save a JBIG2 encoded image"""
        name, path = self._create_unique_image_name(image, ".jb2")
        with open(path, "wb") as fp:
            input_stream = BytesIO()

            global_streams = []
            filters = image.stream.get_filters()
            for filter_name, params in filters:
                if filter_name in LITERALS_JBIG2_DECODE:
                    global_streams.append(params["JBIG2Globals"].resolve())

            if len(global_streams) > 1:
                msg = (
                    "There should never be more than one JBIG2Globals "
                    "associated with a JBIG2 embedded image"
                )
                raise PDFValueError(msg)
            if len(global_streams) == 1:
                input_stream.write(global_streams[0].get_data().rstrip(b"\n"))
            input_stream.write(image.stream.get_data())
            input_stream.seek(0)
            reader = JBIG2StreamReader(input_stream)
            segments = reader.get_segments()

            writer = JBIG2StreamWriter(fp)
            writer.write_file(segments)
        return name

    def _save_bytes(self, image: LTImage) -> str:
        """Save an image without encoding, just bytes"""
        img_stream = image.stream.get_data()
        if image.colorspace[0] is LITERAL_INDEXED:
            hival = int_value(image.colorspace[2])
            lookup = image.colorspace[3]
            if not isinstance(lookup, bytes):
                lookup = stream_value(lookup).get_data()
            channels = len(lookup) // (hival + 1)
            img_stream = bytes(
                b for i in img_stream for b in lookup[channels * i : channels * (i + 1)]
            )
        else:
            width, height = image.srcsize
            channels = len(img_stream) * 8 // (width * height * image.bits)

        mode: Literal["1", "L", "RGB", "CMYK"]
        if image.bits == 1:
            mode = "1"
        elif image.bits == 8 and channels == 1:
            mode = "L"
        elif image.bits == 8 and channels == 3:
            mode = "RGB"
        elif image.bits == 8 and channels == 4:
            mode = "CMYK"
        else:
            return self._save_raw(image)

        ext = ".tiff" if mode == "CMYK" else ".bmp"
        name, path = self._create_unique_image_name(image, ext)
        with open(path, "wb") as fp:
            try:
                from PIL import Image  # type: ignore[import]
            except ImportError:
                raise ImportError(PIL_ERROR_MESSAGE)
            img = Image.frombytes(mode, image.srcsize, img_stream, "raw")
            img.save(fp)

        return name

    def _save_raw(self, image: LTImage) -> str:
        """Save an image with unknown encoding"""
        ext = ".%d.%dx%d.img" % (image.bits, image.srcsize[0], image.srcsize[1])
        name, path = self._create_unique_image_name(image, ext)

        with open(path, "wb") as fp:
            fp.write(image.stream.get_data())
        return name

    @staticmethod
    def _is_jbig2_iamge(image: LTImage) -> bool:
        filters = image.stream.get_filters()
        for filter_name, params in filters:
            if filter_name in LITERALS_JBIG2_DECODE:
                return True
        return False

    def _create_unique_image_name(self, image: LTImage, ext: str) -> Tuple[str, str]:
        name = image.name + ext
        path = os.path.join(self.outdir, name)
        img_index = 0
        while os.path.exists(path):
            name = "%s.%d%s" % (image.name, img_index, ext)
            path = os.path.join(self.outdir, name)
            img_index += 1
        return name, path
