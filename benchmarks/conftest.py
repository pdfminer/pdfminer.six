"""pytest-benchmark configuration for pdfminer.six benchmarks."""

import os
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def samples_dir() -> Path:
    """Return the path to the samples directory."""
    return Path(__file__).parent.parent / "samples"


@pytest.fixture(scope="session")
def simple1_pdf(samples_dir: Path) -> Path:
    """Return path to simple1.pdf - minimal complexity baseline."""
    return samples_dir / "simple1.pdf"


@pytest.fixture(scope="session")
def simple4_pdf(samples_dir: Path) -> Path:
    """Return path to simple4.pdf - moderate complexity (33KB)."""
    return samples_dir / "simple4.pdf"


@pytest.fixture(scope="session")
def simple5_pdf(samples_dir: Path) -> Path:
    """Return path to simple5.pdf - larger file (74KB)."""
    return samples_dir / "simple5.pdf"


@pytest.fixture(scope="session")
def font_size_test_pdf(samples_dir: Path) -> Path:
    """Return path to font-size-test.pdf - complex parsing."""
    return samples_dir / "contrib" / "font-size-test.pdf"


def pytest_configure(config: pytest.Config) -> None:
    """Configure pytest-benchmark with custom settings."""
    # Set benchmark defaults
    config.option.benchmark_min_rounds = 5
    config.option.benchmark_warmup = True
    config.option.benchmark_warmup_iterations = 3

    # Create benchmarks directory for JSON exports
    benchmark_dir = Path(__file__).parent.parent / ".benchmarks"
    benchmark_dir.mkdir(exist_ok=True)
