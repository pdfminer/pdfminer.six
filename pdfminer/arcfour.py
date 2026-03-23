"""Python implementation of Arcfour encryption algorithm.
See https://en.wikipedia.org/wiki/RC4
This code is in the public domain.

"""

from collections.abc import Sequence

from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
from cryptography.hazmat.primitives.ciphers import Cipher


class Arcfour:
    def __init__(self, key: Sequence[int]) -> None:
        self._encryptor = Cipher(ARC4(bytes(key)), mode=None).encryptor()

    def process(self, data: bytes) -> bytes:
        return self._encryptor.update(data)

    encrypt = decrypt = process
