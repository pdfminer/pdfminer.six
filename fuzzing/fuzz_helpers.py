import io
import tempfile
import atheris
import contextlib
from typing import List, Set, Dict, Tuple, Any


class EnhancedFuzzedDataProvider(atheris.FuzzedDataProvider):
    def ConsumeRandomBytes(self) -> bytes:
        return self.ConsumeBytes(self.ConsumeIntInRange(0, self.remaining_bytes()))

    def ConsumeRandomString(self) -> str:
        return self.ConsumeUnicodeNoSurrogates(
            self.ConsumeIntInRange(0, self.remaining_bytes())
        )

    def ConsumeRemainingString(self) -> str:
        return self.ConsumeUnicodeNoSurrogates(self.remaining_bytes())

    def ConsumeRemainingBytes(self) -> bytes:
        return self.ConsumeBytes(self.remaining_bytes())

    @contextlib.contextmanager
    def ConsumeMemoryFile(
        self, all_data: bool = False, as_bytes: bool = True
    ) -> io.BytesIO:
        if all_data:
            file_data = (
                self.ConsumeRemainingBytes()
                if as_bytes
                else self.ConsumeRemainingString()
            )
        else:
            file_data = (
                self.ConsumeRandomBytes() if as_bytes else self.ConsumeRandomString()
            )

        file = io.BytesIO(file_data) if as_bytes else io.StringIO(file_data)
        yield file
        file.close()

    @contextlib.contextmanager
    def ConsumeTemporaryFile(
        self, suffix: str, all_data: bool = False, as_bytes: bool = True
    ) -> str:
        if all_data:
            file_data = (
                self.ConsumeRemainingBytes()
                if as_bytes
                else self.ConsumeRemainingString()
            )
        else:
            file_data = (
                self.ConsumeRandomBytes() if as_bytes else self.ConsumeRandomString()
            )

        mode = "w+b" if as_bytes else "w+"
        tfile = tempfile.NamedTemporaryFile(mode=mode, suffix=suffix)
        tfile.write(file_data)
        tfile.seek(0)
        tfile.flush()
        yield tfile.name
        tfile.close()
