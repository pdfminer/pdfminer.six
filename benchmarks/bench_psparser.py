"""Benchmarks for pdfminer.psparser module."""

import io
from pathlib import Path
from typing import Any

import pytest

from pdfminer.psparser import PSBaseParser, PSStackParser
from pdfminer.psexceptions import PSEOF


class TestPSBaseParserBenchmarks:
    """Benchmarks for PSBaseParser low-level tokenization."""

    @pytest.fixture
    def sample_ps_data(self) -> bytes:
        """Sample PostScript data for benchmarking."""
        return b"""
        /Title (Sample PDF Document)
        /Author (Test User)
        /Subject (Performance Testing)
        /Keywords (pdf benchmark test performance)
        <<
            /Type /Catalog
            /Pages 123 0 R
            /Names << /Dests 456 0 R >>
        >>
        [ 1 2 3 4 5 6 7 8 9 10 ]
        <48656c6c6f20576f726c64>
        (This is a string with some text)
        (String with escape \\n and \\r sequences)
        """

    @pytest.fixture
    def parser(self, sample_ps_data: bytes) -> PSBaseParser:
        """Create a PSBaseParser instance."""
        fp = io.BytesIO(sample_ps_data)
        return PSBaseParser(fp)

    def test_nexttoken(self, benchmark: Any, sample_ps_data: bytes) -> None:
        """Benchmark nexttoken() - most critical hotspot."""

        def parse_all_tokens() -> list:
            fp = io.BytesIO(sample_ps_data)
            parser = PSBaseParser(fp)
            tokens = []
            try:
                while True:
                    token = parser.nexttoken()
                    tokens.append(token)
            except (StopIteration, PSEOF):
                pass
            return tokens

        result = benchmark(parse_all_tokens)
        assert len(result) > 0

    def test_nextline(self, benchmark: Any) -> None:
        """Benchmark nextline() - has bytes concatenation issue."""
        data = b"Line 1\nLine 2\r\nLine 3\rLine 4\n" * 100

        def parse_all_lines() -> list:
            fp = io.BytesIO(data)
            parser = PSBaseParser(fp)
            lines = []
            try:
                while True:
                    pos, line = parser.nextline()
                    lines.append((pos, line))
            except (StopIteration, PSEOF):
                pass
            return lines

        result = benchmark(parse_all_lines)
        assert len(result) > 0

    def test_parse_from_file(self, benchmark: Any, simple4_pdf: Path) -> None:
        """Benchmark parsing tokens from a real PDF file."""

        def parse_pdf_tokens() -> list:
            with open(simple4_pdf, "rb") as fp:
                parser = PSBaseParser(fp)
                tokens = []
                try:
                    # Parse first 1000 tokens
                    for _ in range(1000):
                        token = parser.nexttoken()
                        tokens.append(token)
                except StopIteration:
                    pass
                return tokens

        result = benchmark(parse_pdf_tokens)
        assert len(result) > 0


class TestPSStackParserBenchmarks:
    """Benchmarks for PSStackParser high-level object parsing."""

    @pytest.fixture
    def complex_ps_data(self) -> bytes:
        """Complex PostScript data with nested structures."""
        return b"""
        <<
            /Type /Catalog
            /Version /1.4
            /Pages 1 0 R
            /Names << /Dests 2 0 R /IDS 3 0 R >>
            /Metadata 4 0 R
            /PageLabels << /Nums [ 0 << /S /D >> ] >>
            /StructTreeRoot 5 0 R
            /MarkInfo << /Marked true >>
            /Lang (en-US)
            /ViewerPreferences << /DisplayDocTitle true >>
        >>
        [ 1 2 3 [ 4 5 [ 6 7 8 ] 9 ] 10 ]
        << /Key1 /Value1 /Key2 /Value2 /Key3 [ 1 2 3 ] >>
        """

    def test_nextobject(self, benchmark: Any, complex_ps_data: bytes) -> None:
        """Benchmark nextobject() - full object parsing."""

        def parse_all_objects() -> list:
            fp = io.BytesIO(complex_ps_data)
            parser = PSStackParser(fp)
            objects = []
            try:
                while True:
                    _, obj = parser.nextobject()
                    objects.append(obj)
            except (StopIteration, PSEOF):
                pass
            return objects

        result = benchmark(parse_all_objects)
        assert len(result) > 0

    def test_parse_dict(self, benchmark: Any) -> None:
        """Benchmark dictionary parsing."""
        data = b"<< /Key1 /Value1 /Key2 /Value2 /Key3 /Value3 /Key4 /Value4 >>" * 50

        def parse_dicts() -> list:
            fp = io.BytesIO(data)
            parser = PSStackParser(fp)
            dicts = []
            try:
                while True:
                    _, obj = parser.nextobject()
                    dicts.append(obj)
            except (StopIteration, PSEOF):
                pass
            return dicts

        result = benchmark(parse_dicts)
        assert len(result) > 0

    def test_parse_array(self, benchmark: Any) -> None:
        """Benchmark array parsing."""
        data = b"[ 1 2 3 4 5 6 7 8 9 10 ]" * 100

        def parse_arrays() -> list:
            fp = io.BytesIO(data)
            parser = PSStackParser(fp)
            arrays = []
            try:
                while True:
                    _, obj = parser.nextobject()
                    arrays.append(obj)
            except (StopIteration, PSEOF):
                pass
            return arrays

        result = benchmark(parse_arrays)
        assert len(result) > 0


class TestPSParserSpecificOperations:
    """Benchmarks for specific parser operations (hex strings, escapes, etc.)."""

    def test_hex_string_parsing(self, benchmark: Any) -> None:
        """Benchmark hex string parsing - has nested regex issue."""
        # Mix of hex strings with various lengths and whitespace patterns
        data = b"""
        <48656c6c6f>
        <576f726c64>
        <54 68 69 73 20 69 73 20 61 20 74 65 73 74>
        <0123456789ABCDEF>
        <FF00FF00FF00>
        """ * 50

        def parse_hex_strings() -> list:
            fp = io.BytesIO(data)
            parser = PSBaseParser(fp)
            tokens = []
            try:
                while True:
                    token = parser.nexttoken()
                    tokens.append(token)
            except (StopIteration, PSEOF):
                pass
            return tokens

        result = benchmark(parse_hex_strings)
        assert len(result) > 0

    def test_string_escape_parsing(self, benchmark: Any) -> None:
        """Benchmark string escape parsing."""
        data = b"""
        (Simple string)
        (String with \\n newline)
        (String with \\r carriage return)
        (String with \\t tab)
        (String with \\\\backslash)
        (String with \\(parenthesis\\))
        (String with \\101 octal)
        (Nested (parentheses) work)
        """ * 50

        def parse_strings() -> list:
            fp = io.BytesIO(data)
            parser = PSBaseParser(fp)
            tokens = []
            try:
                while True:
                    token = parser.nexttoken()
                    tokens.append(token)
            except (StopIteration, PSEOF):
                pass
            return tokens

        result = benchmark(parse_strings)
        assert len(result) > 0

    def test_literal_parsing(self, benchmark: Any) -> None:
        """Benchmark literal (name) parsing."""
        data = b"""
        /Type /Catalog /Pages /Names /Dests /IDS
        /Metadata /PageLabels /Nums /StructTreeRoot
        /MarkInfo /Marked /Lang /ViewerPreferences
        """ * 100

        def parse_literals() -> list:
            fp = io.BytesIO(data)
            parser = PSBaseParser(fp)
            tokens = []
            try:
                while True:
                    token = parser.nexttoken()
                    tokens.append(token)
            except (StopIteration, PSEOF):
                pass
            return tokens

        result = benchmark(parse_literals)
        assert len(result) > 0

    def test_number_parsing(self, benchmark: Any) -> None:
        """Benchmark number parsing (integers and floats)."""
        data = b"""
        123 456 789 -123 +456
        1.23 4.56 -7.89 +1.01
        0 0.0 -0 +0
        1234567890 3.141592653589793
        """ * 100

        def parse_numbers() -> list:
            fp = io.BytesIO(data)
            parser = PSBaseParser(fp)
            tokens = []
            try:
                while True:
                    token = parser.nexttoken()
                    tokens.append(token)
            except (StopIteration, PSEOF):
                pass
            return tokens

        result = benchmark(parse_numbers)
        assert len(result) > 0


class TestPSParserRealWorldFiles:
    """Benchmarks using real PDF files."""

    def test_parse_simple1(self, benchmark: Any, simple1_pdf: Path) -> None:
        """Benchmark parsing simple1.pdf (minimal complexity baseline)."""

        def parse_file() -> list:
            with open(simple1_pdf, "rb") as fp:
                parser = PSStackParser(fp)
                objects = []
                try:
                    while True:
                        _, obj = parser.nextobject()
                        objects.append(obj)
                        if len(objects) >= 500:  # Limit for benchmark speed
                            break
                except StopIteration:
                    pass
                return objects

        result = benchmark(parse_file)
        assert len(result) > 0

    def test_parse_simple4(self, benchmark: Any, simple4_pdf: Path) -> None:
        """Benchmark parsing simple4.pdf (moderate complexity, 33KB)."""

        def parse_file() -> list:
            with open(simple4_pdf, "rb") as fp:
                parser = PSStackParser(fp)
                objects = []
                try:
                    while True:
                        _, obj = parser.nextobject()
                        objects.append(obj)
                        if len(objects) >= 1000:  # Limit for benchmark speed
                            break
                except StopIteration:
                    pass
                return objects

        result = benchmark(parse_file)
        assert len(result) > 0
