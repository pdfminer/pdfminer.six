"""Benchmarks for pdfminer.pdftypes module."""

import io
from typing import Any

import pytest

from pdfminer.pdfparser import PDFParser
from pdfminer.pdfdocument import PDFDocument
from pdfminer.pdftypes import resolve_all, PDFObjRef


class TestPDFTypesResolveAllBenchmarks:
    """Benchmarks for resolve_all() function - documented as slow."""

    @pytest.fixture
    def sample_pdf_with_refs(self, tmp_path: Any) -> Any:
        """Create a sample PDF with multiple object references."""
        # Minimal PDF with object references
        pdf_content = b"""%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
2 0 obj
<<
/Type /Pages
/Kids [3 0 R 4 0 R 5 0 R]
/Count 3
>>
endobj
3 0 obj
<<
/Type /Page
/Parent 2 0 R
/Resources 6 0 R
/MediaBox [0 0 612 792]
/Contents 7 0 R
>>
endobj
4 0 obj
<<
/Type /Page
/Parent 2 0 R
/Resources 6 0 R
/MediaBox [0 0 612 792]
/Contents 8 0 R
>>
endobj
5 0 obj
<<
/Type /Page
/Parent 2 0 R
/Resources 6 0 R
/MediaBox [0 0 612 792]
/Contents 9 0 R
>>
endobj
6 0 obj
<<
/Font <<
/F1 10 0 R
>>
>>
endobj
7 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(Page 1) Tj
ET
endstream
endobj
8 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(Page 2) Tj
ET
endstream
endobj
9 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
100 700 Td
(Page 3) Tj
ET
endstream
endobj
10 0 obj
<<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
endobj
xref
0 11
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000127 00000 n
0000000243 00000 n
0000000359 00000 n
0000000475 00000 n
0000000525 00000 n
0000000616 00000 n
0000000707 00000 n
0000000798 00000 n
trailer
<<
/Size 11
/Root 1 0 R
>>
startxref
885
%%EOF
"""
        pdf_file = tmp_path / "test.pdf"
        pdf_file.write_bytes(pdf_content)
        return pdf_file

    def test_resolve_all_simple_dict(self, benchmark: Any) -> None:
        """Benchmark resolve_all() on a simple dictionary without references."""
        simple_dict = {
            "Type": "Catalog",
            "Pages": {"Type": "Pages", "Count": 3},
            "Names": {"Dests": ["Dest1", "Dest2", "Dest3"]},
        }

        result = benchmark(resolve_all, simple_dict)
        assert result is not None

    def test_resolve_all_nested_dict(self, benchmark: Any) -> None:
        """Benchmark resolve_all() on deeply nested dictionary."""
        nested_dict = {
            "Level1": {
                "Level2": {
                    "Level3": {
                        "Level4": {
                            "Level5": {
                                "Data": [1, 2, 3, 4, 5],
                            },
                        },
                    },
                },
            },
        }

        result = benchmark(resolve_all, nested_dict)
        assert result is not None

    def test_resolve_all_with_arrays(self, benchmark: Any) -> None:
        """Benchmark resolve_all() on structures with large arrays."""
        dict_with_arrays = {
            "Array1": list(range(100)),
            "Array2": [{"Key": i, "Value": f"Value{i}"} for i in range(50)],
            "Array3": [[1, 2, 3], [4, 5, 6], [7, 8, 9]] * 10,
        }

        result = benchmark(resolve_all, dict_with_arrays)
        assert result is not None

    def test_resolve_all_from_pdf(
        self,
        benchmark: Any,
        sample_pdf_with_refs: Any,
    ) -> None:
        """Benchmark resolve_all() on actual PDF objects with references."""

        def resolve_catalog() -> Any:
            with open(sample_pdf_with_refs, "rb") as fp:
                parser = PDFParser(fp)
                doc = PDFDocument(parser)
                catalog = doc.catalog
                # This will recursively resolve all references in the catalog
                resolved = resolve_all(catalog)
                return resolved

        result = benchmark(resolve_catalog)
        assert result is not None

    def test_resolve_all_repeated(
        self,
        benchmark: Any,
        sample_pdf_with_refs: Any,
    ) -> None:
        """Benchmark repeated resolve_all() calls (tests caching potential)."""

        def resolve_multiple_times() -> list:
            results = []
            with open(sample_pdf_with_refs, "rb") as fp:
                parser = PDFParser(fp)
                doc = PDFDocument(parser)
                catalog = doc.catalog
                # Resolve the same object multiple times
                # This simulates repeated access patterns
                for _ in range(10):
                    resolved = resolve_all(catalog)
                    results.append(resolved)
            return results

        result = benchmark(resolve_multiple_times)
        assert len(result) == 10
