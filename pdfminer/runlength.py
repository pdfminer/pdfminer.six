#
# RunLength decoder (Adobe version) implementation based on PDF Reference
# version 1.4 section 3.3.4.
#
#  * public domain *
#

from typing import Iterable


EOD = 128  # End-of-data marker for RunLengthDecode


def rldecode(data: bytes) -> bytes:
    """RunLength decoder (Adobe version) implementation.
    See PDF Reference 1.4 section 3.3.4.
    """
    decoded = bytearray()
    data_iter = iter(data)

    while True:
        length = next(data_iter, EOD)
        if length == EOD:
            break

        # Literal run
        if 0 <= length < 128:
            try:
                for _ in range(length + 1):
                    decoded.append(next(data_iter))
            except StopIteration:
                # Truncated literal run — stop gracefully
                break

        # Repeated byte run
        elif length > 128:
            try:
                b = next(data_iter)
            except StopIteration:
                break
            decoded.extend([b] * (257 - length))

    return bytes(decoded)

