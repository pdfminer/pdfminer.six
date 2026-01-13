"""End-to-end benchmarks for measuring overall PDF parsing performance."""

from pathlib import Path
from typing import Any

import pytest

from pdfminer.high_level import extract_text
from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdfpage import PDFPage


class TestEndToEndParsing:
    """End-to-end benchmarks on real PDF files."""

    def test_extract_text_simple1(self, benchmark: Any, simple1_pdf: Path) -> None:
        """Benchmark full text extraction from simple1.pdf (minimal)."""
        result = benchmark(extract_text, str(simple1_pdf))
        assert len(result) > 0

    def test_extract_text_simple4(self, benchmark: Any, simple4_pdf: Path) -> None:
        """Benchmark full text extraction from simple4.pdf (33KB, moderate)."""
        result = benchmark(extract_text, str(simple4_pdf))
        assert len(result) > 0

    def test_extract_text_simple5(self, benchmark: Any, simple5_pdf: Path) -> None:
        """Benchmark full text extraction from simple5.pdf (74KB, larger)."""
        result = benchmark(extract_text, str(simple5_pdf))
        assert len(result) > 0

    def test_parse_document_simple4(self, benchmark: Any, simple4_pdf: Path) -> None:
        """Benchmark parsing PDF document structure (simple4.pdf)."""

        def parse_document() -> int:
            with open(simple4_pdf, "rb") as fp:
                parser = PDFParser(fp)
                doc = PDFDocument(parser)
                page_count = 0
                for page in PDFPage.create_pages(doc):
                    page_count += 1
                return page_count

        result = benchmark(parse_document)
        assert result > 0

    def test_parse_document_simple5(self, benchmark: Any, simple5_pdf: Path) -> None:
        """Benchmark parsing PDF document structure (simple5.pdf)."""

        def parse_document() -> int:
            with open(simple5_pdf, "rb") as fp:
                parser = PDFParser(fp)
                doc = PDFDocument(parser)
                page_count = 0
                for page in PDFPage.create_pages(doc):
                    page_count += 1
                return page_count

        result = benchmark(parse_document)
        assert result > 0


class TestRealWorldPerformance:
    """Benchmarks simulating real-world usage patterns."""

    def test_extract_text_multiple_small_pdfs(
        self,
        benchmark: Any,
        simple1_pdf: Path,
        simple4_pdf: Path,
    ) -> None:
        """Benchmark extracting text from multiple small PDFs (batch processing)."""

        def extract_multiple() -> int:
            total_chars = 0
            for pdf_path in [simple1_pdf, simple4_pdf, simple1_pdf]:
                text = extract_text(str(pdf_path))
                total_chars += len(text)
            return total_chars

        result = benchmark(extract_multiple)
        assert result > 0

    def test_parse_large_pdf(self, benchmark: Any, simple5_pdf: Path) -> None:
        """Benchmark parsing a larger PDF with multiple pages."""

        def parse_large() -> tuple[int, int]:
            with open(simple5_pdf, "rb") as fp:
                parser = PDFParser(fp)
                doc = PDFDocument(parser)
                page_count = 0
                text_length = 0
                for page in PDFPage.create_pages(doc):
                    page_count += 1
                # Also extract text
                text = extract_text(str(simple5_pdf))
                text_length = len(text)
                return (page_count, text_length)

        result = benchmark(parse_large)
        assert result[0] > 0
