"""Benchmarks for pdfminer.pdfinterp module."""

import io
from pathlib import Path
from typing import Any

import pytest

from pdfminer.pdfinterp import PDFContentParser
from pdfminer.psexceptions import PSEOF


class TestPDFContentParserBenchmarks:
    """Benchmarks for PDFContentParser inline data extraction."""

    def test_get_inline_data(self, benchmark: Any) -> None:
        """Benchmark get_inline_data() - has bytes concatenation issue."""
        # Simulate inline image data (common in PDFs)
        data = b"""
        BI
        /W 100
        /H 100
        /BPC 8
        /CS /RGB
        ID
        """ + b"X" * 10000 + b"""
        EI
        """ * 10

        def parse_inline_data() -> list:
            fp = io.BytesIO(data)
            parser = PDFContentParser(fp)
            results = []
            # Simulate multiple inline image extractions
            for _ in range(10):
                fp.seek(0)
                parser = PDFContentParser(fp)
                try:
                    # Find start of inline data (after ID keyword)
                    while True:
                        pos, token = parser.nexttoken()
                        if token == b"ID":
                            # Extract inline data
                            inline_pos, inline_data = parser.get_inline_data(pos + 2)
                            results.append((inline_pos, len(inline_data)))
                            break
                except StopIteration:
                    pass
            return results

        result = benchmark(parse_inline_data)
        assert len(result) > 0

    def test_get_inline_data_small(self, benchmark: Any) -> None:
        """Benchmark get_inline_data() with small inline images."""
        data = b"BI /W 10 /H 10 ID " + b"ABCD" * 25 + b" EI\n" * 100

        def parse_small_inline_data() -> int:
            count = 0
            fp = io.BytesIO(data)
            parser = PDFContentParser(fp)
            try:
                while True:
                    pos, token = parser.nexttoken()
                    if token == b"ID":
                        _, inline_data = parser.get_inline_data(pos + 2)
                        count += 1
            except (StopIteration, PSEOF):
                pass
            return count

        result = benchmark(parse_small_inline_data)
        assert result > 0

    def test_get_inline_data_large(self, benchmark: Any) -> None:
        """Benchmark get_inline_data() with large inline images."""
        # Simulate a large inline image (100KB)
        large_data = b"X" * 100000
        data = b"BI /W 500 /H 500 ID " + large_data + b" EI\n"

        def parse_large_inline_data() -> tuple:
            fp = io.BytesIO(data)
            parser = PDFContentParser(fp)
            try:
                while True:
                    pos, token = parser.nexttoken()
                    if token == b"ID":
                        inline_pos, inline_data = parser.get_inline_data(pos + 2)
                        return (inline_pos, len(inline_data))
            except (StopIteration, PSEOF):
                pass
            return (0, 0)

        result = benchmark(parse_large_inline_data)
        assert result[1] > 0

    def test_parse_content_stream(self, benchmark: Any) -> None:
        """Benchmark parsing a typical PDF content stream."""
        # Typical content stream with text and graphics operations
        data = b"""
        q
        BT
        /F1 12 Tf
        50 750 Td
        (Hello World) Tj
        ET
        Q
        1 0 0 1 100 100 cm
        /Im1 Do
        """ * 50

        def parse_content() -> list:
            fp = io.BytesIO(data)
            parser = PDFContentParser(fp)
            tokens = []
            try:
                while True:
                    pos, token = parser.nexttoken()
                    tokens.append(token)
            except (StopIteration, PSEOF):
                pass
            return tokens

        result = benchmark(parse_content)
        assert len(result) > 0


class TestPDFContentParserRealWorld:
    """Benchmarks using real PDF files with content streams."""

    def test_parse_simple4_content(self, benchmark: Any, simple4_pdf: Path) -> None:
        """Benchmark parsing content from simple4.pdf."""

        def parse_content() -> list:
            with open(simple4_pdf, "rb") as fp:
                parser = PDFContentParser(fp)
                tokens = []
                try:
                    # Parse first 2000 tokens
                    for _ in range(2000):
                        pos, token = parser.nexttoken()
                        tokens.append(token)
                except StopIteration:
                    pass
                return tokens

        result = benchmark(parse_content)
        assert len(result) > 0
