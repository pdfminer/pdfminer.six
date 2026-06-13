"""PNG and TIFF predictor filter reversal for PDF stream decompression.

PDF streams can use predictor filters to improve compression ratio.
This module implements the reversal of PNG prediction filters (types 0-4)
and TIFF predictor 2 (horizontal differencing), which are the most common
predictor types used in PDF.

Reference:
- PNG spec: http://www.libpng.org/pub/png/spec/1.2/PNG-Filters.html
- TIFF spec: https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf
"""

from pdfminer.pdfexceptions import PDFValueError


# ─── Paeth predictor ───────────────────────────────────────────────────────

def paeth_predictor(left: int, above: int, upper_left: int) -> int:
    """Compute the Paeth predictor value used in PNG filter type 4.

    Selects the nearest of left, above, or upper_left based on which
    is closest to the initial estimate p = left + above - upper_left.
    Ties are broken in order: left, above, upper_left.

    Reference: http://www.libpng.org/pub/png/spec/1.2/PNG-Filters.html

    :param left: The byte to the left of the current position.
    :param above: The byte directly above the current position.
    :param upper_left: The byte diagonally above-left.
    :returns: The predictor value (one of left, above, or upper_left).
    """
    # Initial estimate
    p = left + above - upper_left
    # Distances to a, b, c
    pa = abs(p - left)
    pb = abs(p - above)
    pc = abs(p - upper_left)

    # Return nearest of a,b,c breaking ties in order a,b,c
    if pa <= pb and pa <= pc:
        return left
    elif pb <= pc:
        return above
    else:
        return upper_left


# ─── TIFF predictor ────────────────────────────────────────────────────────

def apply_tiff_predictor(
    colors: int, columns: int, bitspercomponent: int, data: bytes
) -> bytes:
    """Reverse the effect of the TIFF predictor 2 (horizontal differencing).

    TIFF predictor 2 applies horizontal differencing before compression.
    This function reverses that by adding each byte to the corresponding
    byte one pixel earlier in the same scanline.

    Reference:
    https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf
    (Section 14, page 64)

    :param colors: Number of color components per pixel.
    :param columns: Number of pixels per scanline.
    :param bitspercomponent: Bits per color component (must be 8).
    :param data: The predictor-encoded data.
    :returns: The decoded data.
    :raises PDFValueError: If bitspercomponent is not 8.
    """
    if bitspercomponent != 8:
        error_msg = f"Unsupported `bitspercomponent': {bitspercomponent}"
        raise PDFValueError(error_msg)
    bpp = colors * (bitspercomponent // 8)
    nbytes = columns * bpp
    buf: list[int] = []
    for scanline_i in range(0, len(data), nbytes):
        raw: list[int] = []
        for i in range(nbytes):
            new_value = data[scanline_i + i]
            if i >= bpp:
                new_value += raw[i - bpp]
                new_value %= 256
            raw.append(new_value)
        buf.extend(raw)

    return bytes(buf)


# ─── PNG predictor ─────────────────────────────────────────────────────────

def apply_png_predictor(
    pred: int,
    colors: int,
    columns: int,
    bitspercomponent: int,
    data: bytes,
) -> bytes:
    """Reverse the effect of the PNG prediction filter on a PDF stream.

    PNG uses 5 filter types (0-4) applied per scanline:
    - Type 0 (None): Raw(x) = Encoded(x)
    - Type 1 (Sub): Raw(x) = Encoded(x) + Raw(x - bpp)
    - Type 2 (Up): Raw(x) = Encoded(x) + Prior(x)
    - Type 3 (Average): Raw(x) = Encoded(x) + floor((Raw(x-bpp) + Prior(x))/2)
    - Type 4 (Paeth): Raw(x) = Encoded(x) + PaethPredictor(Raw(x-bpp), Prior(x), Prior(x-bpp))

    Reference: http://www.libpng.org/pub/png/spec/1.2/PNG-Filters.html

    :param pred: The predictor type (unused, kept for API compatibility).
    :param colors: Number of color components per pixel.
    :param columns: Number of pixels per scanline.
    :param bitspercomponent: Bits per color component (must be 8 or 1).
    :param data: The predictor-encoded data, with one filter type byte per scanline.
    :returns: The decoded data.
    :raises PDFValueError: If bitspercomponent is not 8 or 1, or filter type is unsupported.
    """
    if bitspercomponent not in [8, 1]:
        msg = f"Unsupported `bitspercomponent': {bitspercomponent}"
        raise PDFValueError(msg)

    nbytes = colors * columns * bitspercomponent // 8
    bpp = colors * bitspercomponent // 8  # number of bytes per complete pixel
    buf = bytearray()
    line_above = bytearray(columns)
    for scanline_i in range(0, len(data), nbytes + 1):
        filter_type = data[scanline_i]
        line_encoded = data[scanline_i + 1 : scanline_i + 1 + nbytes]
        raw = bytearray()

        if filter_type == 0:
            # Filter type 0: None
            raw = bytearray(line_encoded)

        elif filter_type == 1:
            # Filter type 1: Sub
            # To reverse the effect of the Sub() filter after decompression,
            # output the following value:
            #   Raw(x) = Sub(x) + Raw(x - bpp)
            # (computed mod 256), where Raw() refers to the bytes already
            #  decoded.
            for j, sub_x in enumerate(line_encoded):
                raw_x_bpp = 0 if j < bpp else raw[j - bpp]
                raw_x = (sub_x + raw_x_bpp) & 255
                raw.append(raw_x)

        elif filter_type == 2:
            # Filter type 2: Up
            # To reverse the effect of the Up() filter after decompression,
            # output the following value:
            #   Raw(x) = Up(x) + Prior(x)
            # (computed mod 256), where Prior() refers to the decoded bytes of
            # the prior scanline.
            for up_x, prior_x in zip(line_encoded, line_above, strict=False):
                raw_x = (up_x + prior_x) & 255
                raw.append(raw_x)

        elif filter_type == 3:
            # Filter type 3: Average
            # To reverse the effect of the Average() filter after
            # decompression, output the following value:
            #    Raw(x) = Average(x) + floor((Raw(x-bpp)+Prior(x))/2)
            # where the result is computed mod 256, but the prediction is
            # calculated in the same way as for encoding. Raw() refers to the
            # bytes already decoded, and Prior() refers to the decoded bytes of
            # the prior scanline.
            for j, average_x in enumerate(line_encoded):
                raw_x_bpp = 0 if j < bpp else raw[j - bpp]
                prior_x = line_above[j]
                raw_x = (average_x + (raw_x_bpp + prior_x) // 2) & 255
                raw.append(raw_x)

        elif filter_type == 4:
            # Filter type 4: Paeth
            # To reverse the effect of the Paeth() filter after decompression,
            # output the following value:
            #    Raw(x) = Paeth(x)
            #             + PaethPredictor(Raw(x-bpp), Prior(x), Prior(x-bpp))
            # (computed mod 256), where Raw() and Prior() refer to bytes
            # already decoded. Exactly the same PaethPredictor() function is
            # used by both encoder and decoder.
            for j, paeth_x in enumerate(line_encoded):
                if j < bpp:
                    raw_x_bpp = 0
                    prior_x_bpp = 0
                else:
                    raw_x_bpp = raw[j - bpp]
                    prior_x_bpp = line_above[j - bpp]
                prior_x = line_above[j]
                paeth = paeth_predictor(raw_x_bpp, prior_x, prior_x_bpp)
                raw_x = (paeth_x + paeth) & 255
                raw.append(raw_x)

        else:
            raise PDFValueError(f"Unsupported predictor value: {filter_type}")

        buf.extend(raw)
        line_above = raw
    return bytes(buf)
