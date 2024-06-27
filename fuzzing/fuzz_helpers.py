import io

from atheris import FuzzedDataProvider


class EnhancedFuzzedDataProvider(FuzzedDataProvider):  # type: ignore[misc]
    def ConsumeRandomBytes(self) -> bytes:
        int_range = self.ConsumeIntInRange(0, self.remaining_bytes())
        return bytes(self.ConsumeBytes(int_range))

    def ConsumeRandomString(self) -> str:
        int_range = self.ConsumeIntInRange(0, self.remaining_bytes())
        return str(self.ConsumeUnicodeNoSurrogates(int_range))

    def ConsumeRemainingString(self) -> str:
        return str(self.ConsumeUnicodeNoSurrogates(self.remaining_bytes()))

    def ConsumeRemainingBytes(self) -> bytes:
        return bytes(self.ConsumeBytes(self.remaining_bytes()))

    def ConsumeMemoryFile(self, all_data: bool = False) -> io.BytesIO:
        if all_data:
            return io.BytesIO(self.ConsumeRemainingBytes())
        else:
            return io.BytesIO(self.ConsumeRandomBytes())
